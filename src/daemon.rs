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
use earendil_crypt::{Fingerprint, IdentitySecret};
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
use crate::{daemon::socks5::socks5_loop, socket::Endpoint};
use crate::{daemon::tcp_forward::tcp_forward_loop, socket::n2r_socket::N2rSocket};
use crate::{daemon::udp_forward::udp_forward_loop, log_error};
use crate::{
    global_rpc::server::REGISTERED_HAVENS,
    haven_util::{haven_loop, HAVEN_FORWARD_DOCK},
};

use self::context::{DEBTS, DELAY_QUEUE, NEIGH_TABLE_NEW};
pub use self::control_protocol_impl::ControlProtErr;

use self::db::db_write;
use self::peel_forward::one_hop_closer;
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

    pub fn identity(&self) -> IdentitySecret {
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
    tracing::info!(
        "daemon starting with fingerprint {}",
        ctx.get(GLOBAL_IDENTITY).public().fingerprint()
    );

    scopeguard::defer!({
        tracing::info!(
            "daemon with fingerprint {} is now DROPPED!",
            ctx.get(GLOBAL_IDENTITY).public().fingerprint()
        )
    });

    // Run the loops
    let _db_sync_loop = ctx.init().db_path.clone().map(|_| {
        Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([ctx], move || db_sync_loop(ctx.clone())
                .map_err(log_error("db_sync_loop"))),
        )
    });

    let _identity_refresh_loop = Immortal::respawn(
        RespawnStrategy::Immediate,
        clone!([ctx], move || clone!([ctx], async move {
            // first insert ourselves
            let am_i_relay = !ctx.init().in_routes.is_empty();
            ctx.get(RELAY_GRAPH)
                .write()
                .insert_identity(IdentityDescriptor::new(
                    ctx.get(GLOBAL_IDENTITY),
                    ctx.get(GLOBAL_ONION_SK),
                    am_i_relay,
                ))?;
            smol::Timer::after(Duration::from_secs(60)).await;
            anyhow::Ok(())
        })),
    );
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

    let _rendezvous_forward_loop = Immortal::respawn(
        RespawnStrategy::Immediate,
        clone!([ctx], move || rendezvous_forward_loop(ctx.clone())
            .map_err(log_error("rendezvous_forward_loop"))),
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
    let socket = Arc::new(N2rSocket::bind(
        ctx.clone(),
        *ctx.get(GLOBAL_IDENTITY),
        Some(GLOBAL_RPC_DOCK),
    ));
    let service = Arc::new(GlobalRpcService(GlobalRpcImpl::new(ctx)));
    nursery!(loop {
        let socket = socket.clone();
        if let Ok((req, endpoint)) = socket.recv_from().await {
            let service = service.clone();
            spawn!(async move {
                let req: JrpcRequest = serde_json::from_str(&String::from_utf8(req.to_vec())?)?;
                let resp = service.respond_raw(req).await;
                socket
                    .send_to(
                        Bytes::from(serde_json::to_string(&resp)?.into_bytes()),
                        endpoint,
                    )
                    .await?;

                anyhow::Ok(())
            })
            .detach();
        }
    })
}

#[instrument(skip(ctx))]
/// Loop that listens to and handles incoming haven forwarding requests
async fn rendezvous_forward_loop(ctx: DaemonContext) -> anyhow::Result<()> {
    let seen_srcs: Cache<(Endpoint, Endpoint), ()> = Cache::builder()
        .max_capacity(100_000)
        .time_to_idle(Duration::from_secs(60 * 60))
        .build();

    let socket = Arc::new(N2rSocket::bind(
        ctx.clone(),
        *ctx.get(GLOBAL_IDENTITY),
        Some(HAVEN_FORWARD_DOCK),
    ));

    loop {
        if let Ok((msg, src_ep)) = socket.recv_from().await {
            let ctx = ctx.clone();
            let (inner, dest_ep): (Bytes, Endpoint) = stdcode::deserialize(&msg)?;
            tracing::trace!("received forward msg, from {}, to {}", src_ep, dest_ep);

            let is_valid_dest = ctx
                .get(REGISTERED_HAVENS)
                .contains_key(&dest_ep.fingerprint);
            let is_seen_src = seen_srcs.contains_key(&(dest_ep, src_ep));

            if is_valid_dest {
                seen_srcs.insert((src_ep, dest_ep), ());
            }
            if is_valid_dest || is_seen_src {
                let body: Bytes = (inner, src_ep).stdcode().into();
                socket.send_to(body, dest_ep).await?;
            } else {
                tracing::warn!("haven {} is not registered with me!", dest_ep.fingerprint);
            }
        };
    }
}

#[tracing::instrument(skip(ctx))]
async fn packet_dispatch_loop(ctx: DaemonContext) -> anyhow::Result<()> {
    let delay_queue = ctx.get(DELAY_QUEUE);
    loop {
        let (pkt, next_peeler) = delay_queue.pop().await;
        if let Some(next_hop) = one_hop_closer(&ctx, next_peeler) {
            let conn = ctx
                .get(NEIGH_TABLE_NEW)
                .get(&next_hop)
                .context(format!("could not find this next hop {next_hop}"))?;

            let _ = conn.try_send((pkt, next_peeler));
            let my_fp = ctx.get(GLOBAL_IDENTITY).public().fingerprint();
            if next_hop != my_fp {
                ctx.get(DEBTS).incr_outgoing(next_hop);
            }
        } else {
            tracing::warn!("no route found to next peeler {next_peeler}");
        }
    }
}

fn route_to_instructs(
    route: Vec<Fingerprint>,
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
                next_fingerprint: next,
            })
        })
        .collect()
}
