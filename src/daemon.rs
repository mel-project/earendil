pub(crate) mod context;
mod control_protocol_impl;

mod debts;
pub(crate) mod dht;

mod db;
mod delay_queue;
mod inout_route;
mod peel_forward;
mod reply_block_store;
mod rrb_balance;
mod settlement;
mod socks5;
mod tcp_forward;
mod udp_forward;

use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use clone_macro::clone;
use earendil_crypt::{NodeId, RelayFingerprint, RelayIdentitySecret};
use earendil_packet::ForwardInstruction;

use earendil_topology::{IdentityDescriptor, RelayGraph};
use futures_util::{stream::FuturesUnordered, StreamExt, TryFutureExt};
use moka::sync::Cache;
use nanorpc::{JrpcRequest, JrpcResponse, RpcService, RpcTransport};
use nanorpc_http::server::HttpRpcServer;

use nursery_macro::nursery;
use smol::Task;
use smolscale::immortal::{Immortal, RespawnStrategy};

use stdcode::StdcodeSerializeExt;
use tracing::instrument;

use std::convert::Infallible;
use std::{sync::Arc, time::Duration};

use crate::control_protocol::ControlClient;
use crate::daemon::socks5::socks5_loop;
use crate::daemon::tcp_forward::tcp_forward_loop;
use crate::socket::n2r_socket::N2rRelaySocket;
use crate::socket::{AnonEndpoint, HavenEndpoint};
use crate::{
    config::ConfigFile,
    daemon::context::{GLOBAL_ONION_SK, RELAY_GRAPH},
    global_rpc::GLOBAL_RPC_DOCK,
};
use crate::{
    config::{InRouteConfig, OutRouteConfig},
    control_protocol::ControlService,
    daemon::inout_route::{in_route_obfsudp, out_route_obfsudp, InRouteContext, OutRouteContext},
};
use crate::{control_protocol::SendMessageError, global_rpc::GlobalRpcService};
use crate::{daemon::context::DaemonContext, global_rpc::server::GlobalRpcImpl};
use crate::{daemon::udp_forward::udp_forward_loop, log_error};
use crate::{
    global_rpc::server::REGISTERED_HAVENS,
    haven_util::{haven_loop, HAVEN_FORWARD_DOCK},
};

use self::context::{DEBTS, DELAY_QUEUE, NEIGH_TABLE_NEW};
pub use self::control_protocol_impl::ControlProtErr;

use self::db::db_write;
use self::peel_forward::{client_one_hop_closer, peel_forward, relay_one_hop_closer};
use self::{context::GLOBAL_IDENTITY, control_protocol_impl::ControlProtocolImpl};

pub struct Daemon {
    pub(crate) ctx: DaemonContext,
    _task: Task<()>,
}

impl Daemon {
    /// Initializes the daemon and starts all background loops
    pub fn init(config: ConfigFile) -> anyhow::Result<Daemon> {
        let ctx = DaemonContext::new(config);
        let context = ctx.clone();
        tracing::info!("starting background task for main_daemon");
        let task = smol::spawn(async move {
            let _ = main_daemon(context).await;
        });
        Ok(Self { ctx, _task: task })
    }

    pub fn is_client(&self) -> bool {
        self.ctx.init().in_routes.is_empty()
    }

    pub fn identity(&self) -> Option<RelayIdentitySecret> {
        *self.ctx.get(GLOBAL_IDENTITY)
    }

    pub fn control_client(&self) -> ControlClient {
        ControlClient::from(DummyControlProtocolTransport {
            inner: ControlService(ControlProtocolImpl::new(self.ctx.clone())),
        })
    }
}

struct DummyControlProtocolTransport {
    inner: ControlService<ControlProtocolImpl>,
}

#[async_trait]
impl RpcTransport for DummyControlProtocolTransport {
    type Error = Infallible;

    async fn call_raw(&self, req: JrpcRequest) -> Result<JrpcResponse, Self::Error> {
        Ok(self.inner.respond_raw(req).await)
    }
}

pub async fn main_daemon(ctx: DaemonContext) -> anyhow::Result<()> {
    let i_am_client = ctx.init().in_routes.is_empty();

    // Run the loops
    if i_am_client {
        tracing::info!("client daemon starting");

        scopeguard::defer!(tracing::info!("client daemon is now DROPPED!"));
    } else {
        tracing::info!(
            "daemon starting with fingerprint {:?}",
            ctx.get(GLOBAL_IDENTITY)
                .expect("only relays have global identities")
                .public()
                .fingerprint()
        );

        scopeguard::defer!({
            tracing::info!(
                "daemon with fingerprint {:?} is now DROPPED!",
                ctx.get(GLOBAL_IDENTITY)
                    .expect("only relays have global identities")
                    .public()
                    .fingerprint()
            )
        });

        let _identity_refresh_loop = Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([ctx], move || clone!([ctx], async move {
                // first insert ourselves
                ctx.get(RELAY_GRAPH)
                    .write()
                    .insert_identity(IdentityDescriptor::new(
                        &ctx.get(GLOBAL_IDENTITY)
                            .expect("only relays have global identities"),
                        ctx.get(GLOBAL_ONION_SK),
                    ))?;
                smol::Timer::after(Duration::from_secs(60)).await;
                anyhow::Ok(())
            })),
        );

        let _rendezvous_forward_loop = Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([ctx], move || rendezvous_forward_loop(ctx.clone())
                .map_err(log_error("rendezvous_forward_loop"))),
        );
    }

    let _state_cache_sync_loop = ctx.init().state_cache.clone().map(|_| {
        Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([ctx], move || db_sync_loop(ctx.clone())
                .map_err(log_error("db_sync_loop"))),
        )
    });

    let _control_protocol = Immortal::respawn(
        RespawnStrategy::Immediate,
        clone!([ctx], move || control_protocol_loop(ctx.clone())
            .map_err(log_error("control_protocol"))),
    );

    let _global_rpc_loop = Immortal::respawn(
        RespawnStrategy::Immediate,
        clone!([ctx], move || global_rpc_loop(ctx.clone())
            .map_err(log_error("global_rpc_loop"))),
    );

    let _packet_dispatch_loop = Immortal::respawn(
        RespawnStrategy::Immediate,
        clone!([ctx], move || packet_dispatch_loop(ctx.clone())),
    );

    let _haven_loops: Vec<Immortal> = ctx
        .init()
        .havens
        .clone()
        .into_iter()
        .map(|cfg| {
            Immortal::respawn(
                RespawnStrategy::Immediate,
                clone!([ctx], move || haven_loop(ctx.clone(), cfg.clone())
                    .map_err(log_error("haven_forward_loop"))),
            )
        })
        .collect();

    // app-level traffic tasks/processes
    let _udp_forward_loops: Vec<Immortal> = ctx
        .init()
        .udp_forwards
        .clone()
        .into_iter()
        .map(|udp_fwd_cfg| {
            Immortal::respawn(
                RespawnStrategy::Immediate,
                clone!([ctx], move || udp_forward_loop(
                    ctx.clone(),
                    udp_fwd_cfg.clone()
                )
                .map_err(log_error("udp_forward_loop"))),
            )
        })
        .collect();

    let _tcp_forward_loops: Vec<Immortal> = ctx
        .init()
        .tcp_forwards
        .clone()
        .into_iter()
        .map(|tcp_fwd_cfg| {
            Immortal::respawn(
                RespawnStrategy::Immediate,
                clone!([ctx], move || tcp_forward_loop(
                    ctx.clone(),
                    tcp_fwd_cfg.clone()
                )
                .map_err(log_error("tcp_forward_loop"))),
            )
        })
        .collect();

    let _socks5_loop = ctx.init().socks5.map(|config| {
        Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([ctx], move || socks5_loop(ctx.clone(), config)),
        )
    });

    let mut route_tasks = FuturesUnordered::new();

    // For every in_routes block, spawn a task to handle incoming stuff
    for (in_route_name, config) in ctx.init().in_routes.iter() {
        let context = InRouteContext {
            in_route_name: in_route_name.clone(),
            daemon_ctx: ctx.clone(),
        };

        match config.clone() {
            InRouteConfig::Obfsudp {
                listen,
                secret,
                link_price,
            } => {
                route_tasks.push(smolscale::spawn(in_route_obfsudp(
                    context.clone(),
                    listen,
                    secret,
                    link_price,
                )));
            }
        }
    }

    // For every out_routes block, spawn a task to handle outgoing stuff
    for (out_route_name, config) in ctx.init().out_routes.iter() {
        match config {
            OutRouteConfig::Obfsudp {
                fingerprint,
                connect,
                cookie,
                link_price,
            } => {
                let context = OutRouteContext {
                    out_route_name: out_route_name.clone(),
                    remote_fingerprint: *fingerprint,
                    daemon_ctx: ctx.clone(),
                };

                route_tasks.push(smolscale::spawn(out_route_obfsudp(
                    context,
                    *connect,
                    *cookie,
                    *link_price,
                )));
            }
        }
    }

    // Join all the tasks. If any of the tasks terminate with an error, that's fatal!
    while let Some(next) = route_tasks.next().await {
        next?;
    }

    Ok(())
}

#[instrument(skip(ctx))]
/// Loop that handles the persistence of contex state
async fn db_sync_loop(ctx: DaemonContext) -> anyhow::Result<()> {
    loop {
        tracing::debug!("DBDBDBDB syncing DB...");
        let global_id = ctx.get(GLOBAL_IDENTITY).stdcode();
        let graph = ctx.clone().get(RELAY_GRAPH).read().stdcode();
        let debts = ctx.get(DEBTS).as_bytes()?;
        let chats = inout_route::chat::serialize_chats(&ctx)?;

        db_write(&ctx, "global_identity", global_id).await?;
        db_write(&ctx, "relay_graph", graph).await?;
        db_write(&ctx, "debts", debts).await?;
        db_write(&ctx, "chats", chats).await?;

        smol::Timer::after(Duration::from_secs(10)).await;
    }
}

#[instrument(skip(ctx))]
/// Loop that handles the control protocol
async fn control_protocol_loop(ctx: DaemonContext) -> anyhow::Result<()> {
    let http = HttpRpcServer::bind(ctx.init().control_listen).await?;
    let service = ControlService(ControlProtocolImpl::new(ctx));
    http.run(service).await?;
    Ok(())
}

#[instrument(skip(ctx))]
/// Loop that listens to and handles incoming GlobalRpc requests
async fn global_rpc_loop(ctx: DaemonContext) -> anyhow::Result<()> {
    let socket = Arc::new(N2rRelaySocket::bind(ctx.clone(), Some(GLOBAL_RPC_DOCK)));
    let service = Arc::new(GlobalRpcService(GlobalRpcImpl::new(ctx)));
    nursery!(loop {
        let socket = socket.clone();
        if let Ok((req, endpoint)) = socket.recv_from().await {
            let service = service.clone();
            spawn!(async move {
                let req: JrpcRequest = serde_json::from_str(&String::from_utf8(req.to_vec())?)?;
                let resp = service.respond_raw(req).await;
                socket.send_to(
                    Bytes::from(serde_json::to_string(&resp)?.into_bytes()),
                    endpoint,
                )?;

                anyhow::Ok(())
            })
            .detach();
        }
    })
}

#[instrument(skip(ctx))]
/// Loop that listens to and handles incoming haven forwarding requests
async fn rendezvous_forward_loop(ctx: DaemonContext) -> anyhow::Result<()> {
    let socket = Arc::new(N2rRelaySocket::bind(ctx.clone(), Some(HAVEN_FORWARD_DOCK)));
    let cache: Cache<AnonEndpoint, HavenEndpoint> = Cache::builder()
        .max_capacity(100_000)
        .time_to_idle(Duration::from_secs(60 * 60))
        .build();

    loop {
        if let Ok((msg, src_ep)) = socket.recv_from().await {
            let ctx = ctx.clone();
            let src_is_client = ctx
                .get(REGISTERED_HAVENS)
                .get_by_key(&src_ep.anon_dest)
                .is_none();

            if src_is_client {
                let (inner, dest_ep): (Bytes, HavenEndpoint) = stdcode::deserialize(&msg)?;
                tracing::trace!("received forward msg, from {}, to {}", src_ep, dest_ep);

                if let Some(haven_anon_id) = ctx
                    .get(REGISTERED_HAVENS)
                    .get_by_value(&dest_ep.fingerprint)
                {
                    let body: Bytes = (inner, src_ep).stdcode().into();

                    cache.insert(src_ep, dest_ep);
                    socket.send_to(body, AnonEndpoint::new(haven_anon_id, dest_ep.dock))?;
                } else {
                    tracing::warn!("haven {} is not registered with me!", dest_ep.fingerprint);
                }
            } else {
                let (inner, dest_ep): (Bytes, AnonEndpoint) = stdcode::deserialize(&msg)?;
                tracing::trace!("received forward msg, from {}, to {}", src_ep, dest_ep);

                if let Some(haven) = cache.get(&dest_ep) {
                    let body: Bytes = (inner, haven).stdcode().into();
                    socket.send_to(body, dest_ep)?;
                }
            }
        };
    }
}

#[tracing::instrument(skip(ctx))]
async fn packet_dispatch_loop(ctx: DaemonContext) -> anyhow::Result<()> {
    let i_am_client = ctx.init().in_routes.is_empty();
    let delay_queue = ctx.get(DELAY_QUEUE);
    loop {
        let (pkt, peeler) = delay_queue.pop().await;

        if i_am_client {
            if let Some(next_hop) = client_one_hop_closer(&ctx, peeler) {
                let conn = ctx
                    .get(NEIGH_TABLE_NEW)
                    .get(&next_hop)
                    .context(format!("could not find this next hop {next_hop}"))?;

                let _ = conn.try_send((pkt, next_hop));
                ctx.get(DEBTS).incr_relay_outgoing(next_hop);
            }
        } else {
            let my_fp = ctx
                .get(GLOBAL_IDENTITY)
                .expect("only relays have global identities")
                .public()
                .fingerprint();

            if peeler == my_fp {
                // todo: don't allow ourselves to be the first hop when choosing forward routes
                peel_forward(&ctx, NodeId::Relay(my_fp), peeler, pkt).await;
            } else if let Some(next_hop) = relay_one_hop_closer(&ctx, peeler) {
                let conn = ctx
                    .get(NEIGH_TABLE_NEW)
                    .get(&next_hop)
                    .context(format!("could not find this next hop {next_hop}"))?;

                let _ = conn.try_send((pkt, peeler));
            } else {
                tracing::warn!("no route found to next peeler {peeler}");
            }
        }
    }
}

fn route_to_instructs(
    route: Vec<RelayFingerprint>,
    relay_graph: &RelayGraph,
) -> Result<Vec<ForwardInstruction>, SendMessageError> {
    route
        .windows(2)
        .map(|wind| {
            let this = wind[0];
            let next = wind[1];

            let this_pubkey = relay_graph
                .identity(&this)
                .ok_or(SendMessageError::NoOnionPublic(this))?
                .onion_pk;
            Ok(ForwardInstruction {
                this_pubkey,
                next_hop: next,
            })
        })
        .collect()
}
