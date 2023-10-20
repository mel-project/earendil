mod gossip;
mod inout_route;
mod n2n_connection;
mod n2n_protocol;
mod neightable;

use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use clone_macro::clone;
use concurrent_queue::ConcurrentQueue;
use earendil_crypt::{Fingerprint, IdentitySecret};
use earendil_packet::RbDegarbler;
use earendil_packet::{
    crypt::OnionSecret, ForwardInstruction, InnerPacket, PeeledPacket, RawPacket, ReplyBlock,
};
use earendil_topology::RelayGraph;
use futures_util::{stream::FuturesUnordered, StreamExt, TryFutureExt};
use lru::LruCache;
use moka::sync::Cache;
use nanorpc_http::server::HttpRpcServer;
use parking_lot::RwLock;
use smolscale::immortal::{Immortal, RespawnStrategy};
use sosistab2::ObfsUdpSecret;
use std::{
    collections::{BTreeMap, VecDeque},
    num::NonZeroUsize,
    path::Path,
    sync::Arc,
    time::Duration,
};

use crate::{
    config::{ConfigFile, InRouteConfig, OutRouteConfig},
    control_protocol::{ControlProtocol, ControlService, SendMessageArgs, SendMessageError},
    daemon::{
        gossip::gossip_loop,
        inout_route::{in_route_obfsudp, out_route_obfsudp, InRouteContext, OutRouteContext},
        neightable::NeighTable,
    },
};

fn log_error<E>(label: &str) -> impl FnOnce(E) + '_
where
    E: std::fmt::Debug,
{
    move |s| log::warn!("{label} restart, error: {:?}", s)
}

pub fn main_daemon(config: ConfigFile) -> anyhow::Result<()> {
    fn read_identity(path: &Path) -> anyhow::Result<IdentitySecret> {
        Ok(stdcode::deserialize(&hex::decode(std::fs::read(path)?)?)?)
    }

    fn write_identity(path: &Path, identity: &IdentitySecret) -> anyhow::Result<()> {
        let encoded_identity = hex::encode(stdcode::serialize(&identity)?);
        std::fs::write(path, encoded_identity)?;
        Ok(())
    }

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("earendil=trace"))
        .init();
    let identity = loop {
        match read_identity(&config.identity) {
            Ok(id) => break id,
            Err(err) => {
                log::warn!(
                    "(re)writing identity file at {:?} due to error reading: {:?}",
                    config.identity,
                    err
                );
                let new_id = IdentitySecret::generate();
                write_identity(&config.identity, &new_id)?;
            }
        }
    };
    log::info!(
        "daemon starting with fingerprint {}",
        identity.public().fingerprint()
    );

    smolscale::block_on(async move {
        let mut subtasks = FuturesUnordered::new();
        let table = Arc::new(NeighTable::new());

        let daemon_ctx = DaemonContext {
            config: Arc::new(config),
            table: table.clone(),
            identity: identity.into(),
            onion_sk: OnionSecret::generate(),
            relay_graph: Arc::new(RwLock::new(RelayGraph::new())),
            incoming: Arc::new(ConcurrentQueue::unbounded()),
            degarblers: Cache::new(1_000_000),
            anon_destinations: Arc::new(RwLock::new(ReplyBlockStore::new(
                NonZeroUsize::new(5000).expect("reply block store can't be of size 0"),
            ))),
        };

        // Run the loops
        let _table_gc = Immortal::spawn(clone!([table], async move {
            loop {
                smol::Timer::after(Duration::from_secs(60)).await;
                table.garbage_collect();
            }
        }));

        let _peel_forward = Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([daemon_ctx], move || peel_forward_loop(daemon_ctx.clone())
                .map_err(log_error("peel_forward"))),
        );
        let _gossip = Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([daemon_ctx], move || gossip_loop(daemon_ctx.clone())
                .map_err(log_error("gossip"))),
        );
        let _control_protocol = Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([daemon_ctx], move || control_protocol_loop(
                daemon_ctx.clone()
            )
            .map_err(log_error("control_protocol"))),
        );

        // For every in_routes block, spawn a task to handle incoming stuff
        for (in_route_name, config) in daemon_ctx.config.in_routes.iter() {
            let context = InRouteContext {
                in_route_name: in_route_name.clone(),
                daemon_ctx: daemon_ctx.clone(),
            };
            match config.clone() {
                InRouteConfig::Obfsudp { listen, secret } => {
                    subtasks.push(smolscale::spawn(in_route_obfsudp(context, listen, secret)));
                }
            }
        }

        // For every out_routes block, spawn a task to handle outgoing stuff
        for (out_route_name, config) in daemon_ctx.config.out_routes.iter() {
            match config {
                OutRouteConfig::Obfsudp {
                    fingerprint,
                    connect,
                    cookie,
                } => {
                    let context = OutRouteContext {
                        out_route_name: out_route_name.clone(),
                        remote_fingerprint: *fingerprint,
                        daemon_ctx: daemon_ctx.clone(),
                    };
                    subtasks.push(smolscale::spawn(out_route_obfsudp(
                        context, *connect, *cookie,
                    )));
                }
            }
        }

        while let Some(next) = subtasks.next().await {
            next?;
        }
        Ok(())
    })
}

/// Loop that handles the control protocol
async fn control_protocol_loop(ctx: DaemonContext) -> anyhow::Result<()> {
    let http = HttpRpcServer::bind(ctx.config.control_listen).await?;
    let service = ControlService(ControlProtocolImpl { ctx });
    http.run(service).await?;
    Ok(())
}

/// Loop that takes incoming packets, peels them, and processes them
async fn peel_forward_loop(ctx: DaemonContext) -> anyhow::Result<()> {
    loop {
        let pkt = ctx.table.recv_raw_packet().await;
        log::debug!("received raw packet");
        let peeled = pkt.peel(&ctx.onion_sk)?;
        log::debug!("peeled packet!");
        match peeled {
            PeeledPacket::Forward {
                to: next_hop,
                pkt: inner,
            } => {
                let conn = ctx
                    .table
                    .lookup(&next_hop)
                    .context("could not find this next hop")?;
                conn.send_raw_packet(inner).await;
            }
            PeeledPacket::Received {
                from: source,
                pkt: inner,
            } => match inner {
                InnerPacket::Message(msg) => {
                    ctx.incoming.push((msg, source))?;
                }
                InnerPacket::ReplyBlocks(reply_blocks) => {
                    ctx.anon_destinations
                        .write()
                        .insert_batch(source, reply_blocks);
                }
            },
            PeeledPacket::Garbled { id: _, pkt: _ } => todo!(),
        }
    }
}

#[allow(unused)]
#[derive(Clone)]
pub struct DaemonContext {
    config: Arc<ConfigFile>,
    table: Arc<NeighTable>,
    identity: Arc<IdentitySecret>,
    onion_sk: OnionSecret,
    relay_graph: Arc<RwLock<RelayGraph>>,
    incoming: Arc<ConcurrentQueue<(Bytes, Fingerprint)>>,
    degarblers: Cache<u64, RbDegarbler>,
    anon_destinations: Arc<RwLock<ReplyBlockStore>>,
}

pub struct ReplyBlockDeque {
    pub deque: VecDeque<ReplyBlock>,
    pub capacity: usize,
}

impl ReplyBlockDeque {
    fn new(capacity: usize) -> Self {
        ReplyBlockDeque {
            deque: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn insert(&mut self, item: ReplyBlock) {
        if self.deque.len() == self.capacity {
            // remove the oldest element
            self.deque.pop_front();
        }
        // add the new element to the end
        self.deque.push_back(item);
    }

    fn pop(&mut self) -> Option<ReplyBlock> {
        self.deque.pop_back()
    }
}

pub struct ReplyBlockStore {
    pub items: LruCache<Fingerprint, ReplyBlockDeque>,
}

impl ReplyBlockStore {
    pub fn new(size: NonZeroUsize) -> Self {
        let items = LruCache::new(size);
        Self { items }
    }

    pub fn insert(&mut self, fingerprint: Fingerprint, rb: ReplyBlock) {
        match self.items.get_mut(&fingerprint) {
            Some(deque) => {
                deque.insert(rb);
            }
            None => {
                let mut deque = ReplyBlockDeque::new(1000);
                deque.insert(rb);
                self.items.put(fingerprint, deque);
            }
        }
    }

    fn insert_batch(&mut self, fingerprint: Fingerprint, items: Vec<ReplyBlock>) {
        for item in items {
            self.insert(fingerprint, item);
        }
    }

    pub fn get(&mut self, fingerprint: &Fingerprint) -> Option<ReplyBlock> {
        match self.items.get_mut(fingerprint) {
            Some(deque) => deque.pop(),
            None => None,
        }
    }

    pub fn contains(&self, fingerprint: &Fingerprint) -> bool {
        self.items.contains(fingerprint)
    }
}

struct ControlProtocolImpl {
    ctx: DaemonContext,
}

#[async_trait]
impl ControlProtocol for ControlProtocolImpl {
    async fn graph_dump(&self) -> String {
        let mut out = String::new();
        out.push_str("graph G {\n");
        for adj in self.ctx.relay_graph.read().all_adjacencies() {
            out.push_str(&format!(
                "{:?} -- {:?}\n",
                adj.left.to_string(),
                adj.right.to_string()
            ));
        }
        out.push_str("}\n");
        out
    }

    async fn send_message(&self, args: SendMessageArgs) -> Result<(), SendMessageError> {
        let is_reply = self
            .ctx
            .anon_destinations
            .read()
            .contains(&args.destination);

        if is_reply {
            log::debug!("sending message with reply block");
            let reply_block = self
                .ctx
                .anon_destinations
                .write()
                .get(&args.destination)
                .unwrap();

            let identity_secret = self.ctx.identity.clone();
            let inner = InnerPacket::Message(Bytes::copy_from_slice(&args.content));
            // TODO: handle error properly
            let raw_packet = RawPacket::from_reply_block(&reply_block, inner, &identity_secret)
                .expect("failed to construct reply block");
            self.ctx.table.inject_asif_incoming(raw_packet).await;
            return Ok(());
        }

        let route = self
            .ctx
            .relay_graph
            .read()
            .find_shortest_path(&self.ctx.identity.public().fingerprint(), &args.destination)
            .ok_or(SendMessageError::NoRoute)?;
        let instructs: Result<Vec<_>, SendMessageError> = route
            .windows(2)
            .map(|wind| {
                let this = wind[0];
                let next = wind[1];
                let this_pubkey = self
                    .ctx
                    .relay_graph
                    .read()
                    .identity(&this)
                    .ok_or(SendMessageError::NoOnionPublic(this))?
                    .onion_pk;
                Ok(ForwardInstruction {
                    this_pubkey,
                    next_fingerprint: next,
                })
            })
            .collect();
        let instructs = instructs?;
        let their_opk = self
            .ctx
            .relay_graph
            .read()
            .identity(&args.destination)
            .ok_or(SendMessageError::NoOnionPublic(args.destination))?
            .onion_pk;
        let wrapped_onion = RawPacket::new(
            &instructs,
            &their_opk,
            InnerPacket::Message(args.content),
            &[0; 20],
            &self.ctx.identity,
        )
        .ok()
        .ok_or(SendMessageError::TooFar)?;
        // we send the onion by treating it as a message addressed to ourselves
        self.ctx.table.inject_asif_incoming(wrapped_onion.0).await;
        Ok(())
    }

    async fn recv_message(&self) -> Option<(Bytes, Fingerprint)> {
        self.ctx.incoming.pop().ok()
    }

    async fn my_routes(&self) -> serde_json::Value {
        let lala: BTreeMap<String, OutRouteConfig> = self
            .ctx
            .config
            .in_routes
            .iter()
            .map(|(k, v)| match v {
                InRouteConfig::Obfsudp { listen, secret } => {
                    let secret =
                        ObfsUdpSecret::from_bytes(*blake3::hash(secret.as_bytes()).as_bytes());
                    (
                        k.clone(),
                        OutRouteConfig::Obfsudp {
                            fingerprint: self.ctx.identity.public().fingerprint(),
                            connect: *listen,
                            cookie: *secret.to_public().as_bytes(),
                        },
                    )
                }
            })
            .collect();
        serde_json::to_value(lala).unwrap()
    }
}
