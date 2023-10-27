mod anon_identities;
mod control_protocol_impl;
mod global_rpc_protocol;
mod gossip;
mod inout_route;
mod n2n_connection;
mod n2n_protocol;
mod neightable;
mod reply_block_store;
mod socket;

use anyhow::Context;
use bytes::Bytes;
use clone_macro::clone;
use concurrent_queue::ConcurrentQueue;
use dashmap::DashMap;
use earendil_crypt::{Fingerprint, IdentitySecret};
use earendil_packet::{crypt::OnionSecret, InnerPacket, PeeledPacket};
use earendil_packet::{Dock, ForwardInstruction, Message, RawPacket, ReplyBlock, ReplyDegarbler};
use earendil_topology::RelayGraph;
use futures_util::{stream::FuturesUnordered, StreamExt, TryFutureExt};
use moka::sync::Cache;
use nanorpc::{JrpcRequest, RpcService};
use nanorpc_http::server::HttpRpcServer;
use parking_lot::RwLock;
use smol::channel::{Receiver, Sender};
use smolscale::immortal::{Immortal, RespawnStrategy};
use smolscale::reaper::TaskReaper;

use std::{path::Path, sync::Arc, time::Duration};

use crate::control_protocol::{SendMessageArgs, SendMessageError};
use crate::daemon::anon_identities::AnonIdentities;
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

use self::control_protocol_impl::ControlProtocolImpl;
use self::global_rpc_protocol::{GlobalRpcImpl, GlobalRpcService, GLOBAL_RPC_DOCK};
use self::socket::Socket;

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
        let (incoming_send, incoming_recv) = smol::channel::bounded(1_000_000);

        let daemon_ctx = DaemonContext {
            config: Arc::new(config),
            table: table.clone(),
            identity: identity.into(),
            onion_sk: OnionSecret::generate(),
            relay_graph: Arc::new(RwLock::new(RelayGraph::new())),
            incoming: Arc::new(incoming_recv),
            degarblers: Cache::new(1_000_000),
            anon_destinations: Arc::new(RwLock::new(ReplyBlockStore::new())),
            anon_identities: Arc::new(RwLock::new(AnonIdentities::new())),
            socket_recv_queues: Arc::new(DashMap::new()),
            debug_queue: Arc::new(ConcurrentQueue::unbounded()),
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
            clone!([daemon_ctx], move || peel_forward_loop(
                daemon_ctx.clone(),
                incoming_send.clone()
            )
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

        let _dispatch_by_dock = Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([daemon_ctx], move || dispatch_by_dock_loop(
                daemon_ctx.clone()
            )
            .map_err(log_error("dispatch_by_dock"))),
        );

        let _global_rpc_loop = Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([daemon_ctx], move || global_rpc_loop(daemon_ctx.clone())
                .map_err(log_error("global_rpc_loop"))),
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
async fn peel_forward_loop(
    ctx: DaemonContext,
    incoming_send: Sender<(Message, Fingerprint)>,
) -> anyhow::Result<()> {
    fn process_inner_pkt(
        ctx: &DaemonContext,
        incoming_send: &Sender<(Message, Fingerprint)>,
        inner: InnerPacket,
        source: Fingerprint,
    ) -> anyhow::Result<()> {
        match inner {
            InnerPacket::Message(msg) => {
                log::debug!("received InnerPacket::Message");
                incoming_send.try_send((msg, source))?;
            }
            InnerPacket::ReplyBlocks(reply_blocks) => {
                log::debug!("received a batch of ReplyBlocks");

                for reply_block in reply_blocks {
                    ctx.anon_destinations.write().insert(source, reply_block);
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
                from: source,
                pkt: inner,
            } => process_inner_pkt(&ctx, &incoming_send, inner, source)?,
            PeeledPacket::GarbledReply { id, mut pkt } => {
                log::debug!("received garbled packet");
                let reply_degarbler = ctx
                    .degarblers
                    .get(&id)
                    .context("no degarbler for this garbled pkt")?;
                let (inner, source) = reply_degarbler.degarble(&mut pkt)?;
                log::debug!("packet has been degarbled!");
                process_inner_pkt(&ctx, &incoming_send, inner, source)?
            }
        }
    }
}

/// Loop that dispatches received messages to their corresponding dock queue
async fn dispatch_by_dock_loop(ctx: DaemonContext) -> anyhow::Result<()> {
    loop {
        if let Some((message, fingerprint)) = ctx.recv_message().await {
            match ctx.socket_recv_queues.get(message.get_dest_dock()) {
                Some(sender) => sender.try_send((message, fingerprint))?,
                None => ctx.debug_queue.push((message, fingerprint))?,
            }
        }
    }
}

/// Loop that listens to and handles incoming GlobalRpc requests
async fn global_rpc_loop(ctx: DaemonContext) -> anyhow::Result<()> {
    let socket = Arc::new(Socket::bind(ctx.clone(), None, Some(GLOBAL_RPC_DOCK)));
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

#[allow(unused)]
#[derive(Clone)]
pub struct DaemonContext {
    config: Arc<ConfigFile>,
    table: Arc<NeighTable>,
    identity: Arc<IdentitySecret>,
    onion_sk: OnionSecret,
    relay_graph: Arc<RwLock<RelayGraph>>,
    incoming: Arc<Receiver<(Message, Fingerprint)>>,
    degarblers: Cache<u64, ReplyDegarbler>,
    anon_destinations: Arc<RwLock<ReplyBlockStore>>,
    anon_identities: Arc<RwLock<AnonIdentities>>,
    socket_recv_queues: Arc<DashMap<Dock, Sender<(Message, Fingerprint)>>>,
    debug_queue: Arc<ConcurrentQueue<(Message, Fingerprint)>>,
}

impl DaemonContext {
    async fn send_message(&self, args: SendMessageArgs) -> Result<(), SendMessageError> {
        let (public_isk, my_anon_osk) = if let Some(id) = args.id {
            // get anonymous identity
            let (anon_id, anon_osk) = self.anon_identities.write().get(&id);
            log::debug!(
                "using anon identity with fingerprint {:?}",
                anon_id.public().fingerprint()
            );
            (Arc::new(anon_id), Some(anon_osk))
        } else {
            (self.identity.clone(), None)
        };

        let maybe_reply_block = self.anon_destinations.write().pop(&args.destination);
        if let Some(reply_block) = maybe_reply_block {
            if my_anon_osk.is_some() {
                return Err(SendMessageError::NoAnonId);
            }
            log::debug!("sending message with reply block");
            let inner = InnerPacket::Message(Message::new(
                args.source_dock,
                args.dest_dock,
                Bytes::copy_from_slice(&args.content),
            ));
            let raw_packet = RawPacket::new_reply(&reply_block, inner, &public_isk)?;
            self.table.inject_asif_incoming(raw_packet).await;
        } else {
            let route = self
                .relay_graph
                .read()
                .find_shortest_path(&self.identity.public().fingerprint(), &args.destination)
                .ok_or(SendMessageError::NoRoute)?;
            let instructs = route_to_instructs(route, self.relay_graph.clone())?;
            log::debug!("instructs = {:?}", instructs);
            let their_opk = self
                .relay_graph
                .read()
                .identity(&args.destination)
                .ok_or(SendMessageError::NoOnionPublic(args.destination))?
                .onion_pk;
            let wrapped_onion = RawPacket::new_normal(
                &instructs,
                &their_opk,
                InnerPacket::Message(Message::new(args.source_dock, args.dest_dock, args.content)),
                &public_isk,
            )?;
            // we send the onion by treating it as a message addressed to ourselves
            self.table.inject_asif_incoming(wrapped_onion).await;

            // if we want to use an anon source, send a batch of reply blocks
            if let Some(my_anon_osk) = my_anon_osk {
                // currently the path for every one of them is the same; will want to change this in the future
                let n = 8;
                let reverse_route = self
                    .relay_graph
                    .read()
                    .find_shortest_path(&args.destination, &self.identity.public().fingerprint())
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

    async fn recv_message(&self) -> Option<(Message, Fingerprint)> {
        self.incoming.recv().await.ok()
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
