mod control_protocol_impl;
mod global_rpc;
mod gossip;
pub mod haven;
mod haven_socket;
mod inout_route;
mod link_connection;
mod link_protocol;
pub mod n2r_socket;
mod neightable;
mod reply_block_store;
mod socket;

use anyhow::Context;
use bytes::Bytes;
use clone_macro::clone;
use dashmap::DashMap;
use earendil_crypt::{Fingerprint, IdentitySecret};
use earendil_packet::{crypt::OnionSecret, InnerPacket, PeeledPacket};
use earendil_packet::{Dock, ForwardInstruction, Message, RawPacket, ReplyBlock, ReplyDegarbler};
use earendil_topology::RelayGraph;
use futures_util::{stream::FuturesUnordered, StreamExt, TryFutureExt};
use moka::sync::{Cache, CacheBuilder};
use nanorpc::{JrpcRequest, RpcService};
use nanorpc_http::server::HttpRpcServer;
use parking_lot::{Mutex, RwLock};
use smol::channel::Sender;
use smol_timeout::TimeoutExt;
use smolscale::immortal::{Immortal, RespawnStrategy};
use smolscale::reaper::TaskReaper;
use stdcode::StdcodeSerializeExt;

use std::{path::Path, sync::Arc, time::Duration};

use crate::control_protocol::{DhtError, SendMessageError};
use crate::daemon::global_rpc::transport::GlobalRpcTransport;
use crate::daemon::global_rpc::GlobalRpcClient;
use crate::daemon::reply_block_store::ReplyBlockStore;
use crate::{
    config::{ConfigFile, InRouteConfig, OutRouteConfig},
    control_protocol::ControlService,
    daemon::{
        gossip::gossip_loop,
        inout_route::{in_route_obfsudp, out_route_obfsudp, InRouteContext, OutRouteContext},
        neightable::NeighTable,
    },
};

pub use self::control_protocol_impl::ControlProtRecvErr;
pub use self::control_protocol_impl::ControlProtSendErr;
use self::global_rpc::{GlobalRpcService, GLOBAL_RPC_DOCK};
use self::haven::HavenLocator;
use self::haven::HAVEN_FORWARD_DOCK;
use self::n2r_socket::{Endpoint, N2rSocket};
use self::{control_protocol_impl::ControlProtocolImpl, global_rpc::server::GlobalRpcImpl};

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
        let table = Arc::new(NeighTable::new());
        let daemon_ctx = DaemonContext {
            config: Arc::new(config),
            table: table.clone(),
            identity: identity.into(),
            onion_sk: OnionSecret::generate(),
            relay_graph: Arc::new(RwLock::new(RelayGraph::new())),
            degarblers: Cache::new(1_000_000),
            anon_destinations: Arc::new(Mutex::new(ReplyBlockStore::new())),

            socket_recv_queues: Arc::new(DashMap::new()),
            dht_cache: CacheBuilder::default()
                .time_to_idle(Duration::from_secs(60 * 60))
                .build(),
            registered_havens: Arc::new(
                Cache::builder()
                    .max_capacity(100_000)
                    .time_to_idle(Duration::from_secs(60 * 60))
                    .build(),
            ),
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

        let _global_rpc_loop = Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([daemon_ctx], move || global_rpc_loop(daemon_ctx.clone())
                .map_err(log_error("global_rpc_loop"))),
        );

        let _rendezvous_forward_loop = Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([daemon_ctx], move || rendezvous_forward_loop(
                daemon_ctx.clone()
            )
            .map_err(log_error("haven_forward_loop"))),
        );

        let mut route_tasks = FuturesUnordered::new();

        // For every in_routes block, spawn a task to handle incoming stuff
        for (in_route_name, config) in daemon_ctx.config.in_routes.iter() {
            let context = InRouteContext {
                in_route_name: in_route_name.clone(),
                daemon_ctx: daemon_ctx.clone(),
            };
            match config.clone() {
                InRouteConfig::Obfsudp { listen, secret } => {
                    route_tasks.push(smolscale::spawn(in_route_obfsudp(context, listen, secret)));
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
                    route_tasks.push(smolscale::spawn(out_route_obfsudp(
                        context, *connect, *cookie,
                    )));
                }
            }
        }

        // Join all the tasks. If any of the tasks terminate with an error, that's fatal!
        while let Some(next) = route_tasks.next().await {
            next?;
        }
        Ok(())
    })
}

/// Loop that handles the control protocol
async fn control_protocol_loop(ctx: DaemonContext) -> anyhow::Result<()> {
    let http = HttpRpcServer::bind(ctx.config.control_listen).await?;
    let service = ControlService(ControlProtocolImpl::new(ctx));
    http.run(service).await?;
    Ok(())
}

/// Loop that takes incoming packets, peels them, and processes them
async fn peel_forward_loop(ctx: DaemonContext) -> anyhow::Result<()> {
    fn process_inner_pkt(
        ctx: &DaemonContext,
        inner: InnerPacket,
        src_fp: Fingerprint,
        dest_fp: Fingerprint,
    ) -> anyhow::Result<()> {
        match inner {
            InnerPacket::Message(msg) => {
                // log::debug!("received InnerPacket::Message: {:?}", msg);
                let dest = Endpoint::new(dest_fp, msg.dest_dock);
                if let Some(send_incoming) = ctx.socket_recv_queues.get(&dest) {
                    send_incoming.try_send((msg, src_fp))?;
                } else {
                    anyhow::bail!("No socket listening on destination {dest}")
                }
            }
            InnerPacket::ReplyBlocks(reply_blocks) => {
                log::debug!("received a batch of ReplyBlocks");
                for reply_block in reply_blocks {
                    ctx.anon_destinations.lock().insert(src_fp, reply_block);
                }
            }
        }
        Ok(())
    }

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
                from: src_fp,
                pkt: inner,
            } => process_inner_pkt(&ctx, inner, src_fp, ctx.identity.public().fingerprint())?,
            PeeledPacket::GarbledReply { id, mut pkt } => {
                log::debug!("received garbled packet");
                let reply_degarbler = ctx
                    .degarblers
                    .get(&id)
                    .context("no degarbler for this garbled pkt")?;
                let (inner, src_fp) = reply_degarbler.degarble(&mut pkt)?;
                log::debug!("packet has been degarbled!");
                process_inner_pkt(
                    &ctx,
                    inner,
                    src_fp,
                    reply_degarbler.my_anon_isk().public().fingerprint(),
                )?
            }
        }
    }
}

/// Loop that listens to and handles incoming GlobalRpc requests
async fn global_rpc_loop(ctx: DaemonContext) -> anyhow::Result<()> {
    let socket = Arc::new(N2rSocket::bind(ctx.clone(), None, Some(GLOBAL_RPC_DOCK)));
    let service = Arc::new(GlobalRpcService(GlobalRpcImpl::new(ctx)));
    let group: TaskReaper<anyhow::Result<()>> = TaskReaper::new();

    loop {
        let socket = socket.clone();
        if let Ok((req, endpoint)) = socket.recv_from().await {
            let service = service.clone();
            group.attach(smolscale::spawn(async move {
                let req: JrpcRequest = serde_json::from_str(&String::from_utf8(req.to_vec())?)?;
                let resp = service.respond_raw(req).await;
                socket
                    .send_to(
                        Bytes::from(serde_json::to_string(&resp)?.into_bytes()),
                        endpoint,
                    )
                    .await?;

                Ok(())
            }));
        }
    }
}

const DHT_REDUNDANCY: usize = 3;
/// Loop that listens to and handles incoming haven forwarding requests
async fn rendezvous_forward_loop(ctx: DaemonContext) -> anyhow::Result<()> {
    let seen_srcs: Cache<(Endpoint, Endpoint), ()> = Cache::builder()
        .max_capacity(100_000)
        .time_to_idle(Duration::from_secs(60 * 60))
        .build();
    let socket = Arc::new(N2rSocket::bind(ctx.clone(), None, Some(HAVEN_FORWARD_DOCK)));

    loop {
        if let Ok((msg, src_endpoint)) = socket.recv_from().await {
            let ctx = ctx.clone();
            let (inner, dest_ep): (Bytes, Endpoint) = stdcode::deserialize(&msg)?;
            log::debug!(
                "received forward msg {:?}, from {}, to {}",
                inner,
                src_endpoint,
                dest_ep
            );

            let is_valid_dest = ctx.registered_havens.contains_key(&dest_ep.fingerprint);
            let is_seen_src = seen_srcs.contains_key(&(dest_ep, src_endpoint));

            if is_valid_dest {
                seen_srcs.insert((src_endpoint, dest_ep), ());
            }
            if is_valid_dest || is_seen_src {
                let body: Bytes = (inner, src_endpoint).stdcode().into();
                socket.send_to(body, dest_ep).await?;
            } else {
                log::warn!("haven {} is not registered with me!", dest_ep.fingerprint);
            }
        };
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
    degarblers: Cache<u64, ReplyDegarbler>,
    anon_destinations: Arc<Mutex<ReplyBlockStore>>,
    socket_recv_queues: Arc<DashMap<Endpoint, Sender<(Message, Fingerprint)>>>,
    dht_cache: Cache<Fingerprint, HavenLocator>,
    registered_havens: Arc<Cache<Fingerprint, ()>>,
}

impl DaemonContext {
    async fn send_message(
        &self,
        src_anon_id: Option<IdentitySecret>,
        src_dock: Dock,
        dst_fp: Fingerprint,
        dst_dock: Dock,
        content: Bytes,
    ) -> Result<(), SendMessageError> {
        let (public_isk, my_anon_osk) = if let Some(anon_id) = src_anon_id {
            (Arc::new(anon_id), Some(OnionSecret::generate()))
        } else {
            (self.identity.clone(), None)
        };

        let maybe_reply_block = self.anon_destinations.lock().pop(&dst_fp);
        if let Some(reply_block) = maybe_reply_block {
            if my_anon_osk.is_some() {
                return Err(SendMessageError::NoAnonId);
            }
            log::debug!("sending message with reply block");
            let inner = InnerPacket::Message(Message::new(src_dock, dst_dock, content));
            let raw_packet = RawPacket::new_reply(&reply_block, inner, &public_isk)?;
            self.table.inject_asif_incoming(raw_packet).await;
        } else {
            let route = self
                .relay_graph
                .read()
                .find_shortest_path(&self.identity.public().fingerprint(), &dst_fp)
                .ok_or(SendMessageError::NoRoute)?;
            let instructs = route_to_instructs(route, self.relay_graph.clone())?;
            let their_opk = self
                .relay_graph
                .read()
                .identity(&dst_fp)
                .ok_or(SendMessageError::NoOnionPublic(dst_fp))?
                .onion_pk;
            let wrapped_onion = RawPacket::new_normal(
                &instructs,
                &their_opk,
                InnerPacket::Message(Message::new(src_dock, dst_dock, content)),
                &public_isk,
            )?;
            // we send the onion by treating it as a message addressed to ourselves
            self.table.inject_asif_incoming(wrapped_onion).await;

            // if we want to use an anon source, send a batch of reply blocks
            // TODO this should be replaced
            if let Some(my_anon_osk) = my_anon_osk {
                // currently the path for every one of them is the same; will want to change this in the future
                let n = 8;
                let reverse_route = self
                    .relay_graph
                    .read()
                    .find_shortest_path(&dst_fp, &self.identity.public().fingerprint())
                    .ok_or(SendMessageError::NoRoute)?;
                let reverse_instructs =
                    route_to_instructs(reverse_route, self.relay_graph.clone())?;
                log::debug!("reverse_instructs = {:?}", reverse_instructs);

                let mut rbs: Vec<ReplyBlock> = vec![];
                for _ in 0..n {
                    let (rb, (id, degarbler)) = ReplyBlock::new(
                        &reverse_instructs,
                        &self.onion_sk.public(),
                        my_anon_osk.clone(),
                        (*public_isk).clone(),
                    )
                    .map_err(|_| SendMessageError::ReplyBlockFailed)?;
                    rbs.push(rb);
                    self.degarblers.insert(id, degarbler);
                }
                let wrapped_rb_onion = RawPacket::new_normal(
                    &instructs,
                    &their_opk,
                    InnerPacket::ReplyBlocks(rbs),
                    &public_isk,
                )?;
                // we send the onion by treating it as a message addressed to ourselves
                self.table.inject_asif_incoming(wrapped_rb_onion).await;
            }
        }
        Ok(())
    }

    fn dht_key_to_fps(&self, key: &str) -> Vec<Fingerprint> {
        let mut all_nodes: Vec<Fingerprint> = self.relay_graph.read().all_nodes().collect();
        all_nodes.sort_unstable_by_key(|fp| *blake3::hash(&(key, fp).stdcode()).as_bytes());
        all_nodes
    }

    pub async fn dht_insert(&self, locator: HavenLocator) {
        let key = locator.identity_pk.fingerprint();
        let replicas = self.dht_key_to_fps(&key.to_string());

        for replica in replicas.into_iter().take(DHT_REDUNDANCY) {
            log::debug!("key {key} inserting into remote replica {replica}");
            let gclient = GlobalRpcClient(GlobalRpcTransport::new(self.clone(), replica));
            match gclient
                .dht_insert(locator.clone(), false)
                .timeout(Duration::from_secs(60))
                .await
            {
                Some(Err(e)) => log::debug!("inserting {key} into {replica} failed: {:?}", e),
                None => log::debug!("inserting {key} into {replica} timed out"),
                _ => {}
            }
        }
    }

    pub async fn dht_get(
        &self,
        fingerprint: Fingerprint,
    ) -> Result<Option<HavenLocator>, DhtError> {
        let replicas = self.dht_key_to_fps(&fingerprint.to_string());
        let mut gatherer = FuturesUnordered::new();
        for replica in replicas.into_iter().take(DHT_REDUNDANCY) {
            gatherer.push(async move {
                let gclient = GlobalRpcClient(GlobalRpcTransport::new(self.clone(), replica));
                anyhow::Ok(
                    gclient
                        .dht_get(fingerprint, false)
                        .timeout(Duration::from_secs(30))
                        .await
                        .context("timed out")??,
                )
            })
        }
        while let Some(result) = gatherer.next().await {
            match result {
                Err(err) => log::warn!("error while dht_get: {:?}", err),
                Ok(Err(err)) => log::warn!("error while dht_get: {:?}", err),
                Ok(Ok(None)) => continue,
                Ok(Ok(Some(locator))) => {
                    let id_pk = locator.identity_pk;
                    let payload = locator.to_sign();
                    if id_pk.fingerprint() == fingerprint {
                        id_pk.verify(&payload, &locator.signature)?;
                        return Ok(Some(locator));
                    }
                }
            }
        }
        Ok(None)
    }
}

fn route_to_instructs(
    route: Vec<Fingerprint>,
    relay_graph: Arc<RwLock<RelayGraph>>,
) -> Result<Vec<ForwardInstruction>, SendMessageError> {
    route
        .windows(2)
        .map(|wind| {
            let this = wind[0];
            let next = wind[1];
            let this_pubkey = relay_graph
                .read()
                .identity(&this)
                .ok_or(SendMessageError::NoOnionPublic(this))?
                .onion_pk;
            Ok(ForwardInstruction {
                this_pubkey,
                next_fingerprint: next,
            })
        })
        .collect()
}
