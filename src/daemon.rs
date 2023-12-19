pub(crate) mod context;
mod control_protocol_impl;

pub(crate) mod dht;
mod gossip;
mod inout_route;
mod link_connection;
mod link_protocol;
mod neightable;
mod peel_forward;
mod reply_block_store;
mod rrb_balance;
mod socks5;
mod tcp_forward;
mod udp_forward;

use anyhow::Context;
use bytes::Bytes;
use clone_macro::clone;
use earendil_crypt::{Fingerprint, IdentitySecret};
use earendil_packet::ForwardInstruction;

use earendil_topology::RelayGraph;
use futures_util::{stream::FuturesUnordered, StreamExt, TryFutureExt};
use moka::sync::Cache;
use nanorpc::{JrpcRequest, RpcService};
use nanorpc_http::server::HttpRpcServer;

use smolscale::immortal::{Immortal, RespawnStrategy};
use smolscale::reaper::TaskReaper;
use sosistab2::{Multiplex, MuxSecret, Pipe};
use sosistab2_obfsudp::{ObfsUdpPipe, ObfsUdpPublic};
use stdcode::StdcodeSerializeExt;

use std::thread::available_parallelism;

use std::{sync::Arc, time::Duration};

use crate::daemon::link_connection::{
    connection_loop, LinkConnection, LinkProtocolImpl, MultiplexRpcTransport,
};
use crate::daemon::link_protocol::{LinkClient, LinkService};
use crate::socket::Endpoint;
use crate::{config::ConfigFile, global_rpc::GLOBAL_RPC_DOCK};
use crate::{
    config::{InRouteConfig, OutRouteConfig},
    control_protocol::ControlService,
    daemon::{
        gossip::gossip_loop,
        inout_route::{in_route_obfsudp, out_route_obfsudp, InRouteContext, OutRouteContext},
    },
};
use crate::{control_protocol::SendMessageError, global_rpc::GlobalRpcService};
use crate::{daemon::context::DaemonContext, global_rpc::server::GlobalRpcImpl};
use crate::{daemon::context::NEIGH_TABLE, socket::n2r_socket::N2rSocket};
use crate::{
    daemon::{
        peel_forward::peel_forward_loop, socks5::socks5_loop, tcp_forward::tcp_forward_loop,
        udp_forward::udp_forward_loop,
    },
    log_error,
};
use crate::{
    global_rpc::server::REGISTERED_HAVENS,
    haven_util::{haven_loop, HAVEN_FORWARD_DOCK},
};

pub use self::control_protocol_impl::ControlProtErr;

use self::{context::GLOBAL_IDENTITY, control_protocol_impl::ControlProtocolImpl};

pub struct Daemon {
    pub(crate) ctx: DaemonContext,
    _task: Immortal,
}

impl Daemon {
    /// Initializes the daemon and starts all background loops
    pub fn init(config: ConfigFile) -> anyhow::Result<Daemon> {
        let ctx = DaemonContext::new(config);
        let context = ctx.clone();
        log::info!("starting background task for main_daemon");
        let task = Immortal::spawn(async move {
            main_daemon(context).await.unwrap();
            panic!("daemon failed to start!")
        });
        Ok(Self { ctx, _task: task })
    }

    pub fn identity(&self) -> IdentitySecret {
        *self.ctx.get(GLOBAL_IDENTITY)
    }
}

pub async fn main_daemon(ctx: DaemonContext) -> anyhow::Result<()> {
    log::info!(
        "daemon starting with fingerprint {}",
        ctx.get(GLOBAL_IDENTITY).public().fingerprint()
    );

    scopeguard::defer!({
        log::info!(
            "daemon with fingerprint {} is now DROPPED!",
            ctx.get(GLOBAL_IDENTITY).public().fingerprint()
        )
    });

    // Run the loops
    let _table_gc = Immortal::spawn(clone!([ctx], async move {
        loop {
            smol::Timer::after(Duration::from_secs(60)).await;
            ctx.get(NEIGH_TABLE).garbage_collect();
        }
    }));

    let _peel_forward_loops: Vec<Immortal> =
        (0..available_parallelism().map(|s| s.into()).unwrap_or(1))
            .map(|_| {
                Immortal::respawn(
                    RespawnStrategy::Immediate,
                    clone!([ctx], move || peel_forward_loop(ctx.clone())
                        .map_err(log_error("peel_forward"))),
                )
            })
            .collect();

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

    let _socks5_loop = ctx.init().socks5.clone().map(|config| {
        Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([ctx], move || socks5_loop(ctx.clone(), config.clone(),)),
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
            InRouteConfig::Obfsudp { listen, secret } => {
                let listener = in_route_obfsudp(context, listen, secret).await?;
                loop {
                    let pipe = listener.accept().await?;
                    route_tasks.push(smolscale::spawn(per_route_loop(ctx.clone(), pipe, None)));
                }
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
            } => {
                let context = OutRouteContext {
                    out_route_name: out_route_name.clone(),
                    remote_fingerprint: *fingerprint,
                    daemon_ctx: ctx.clone(),
                };
                let pipe = out_route_obfsudp(context, *connect, *cookie).await?;
                route_tasks.push(smolscale::spawn(per_route_loop(
                    ctx.clone(),
                    pipe,
                    Some(*fingerprint),
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

// NOTE: Do these concurrently:
// Host LinkRPC, using the existing helper structs (LinkProtocol’s generated structs, MultiplexRpcTransport, LinkProtocolImpl, etc)
// Do gossip logic
// Do debt-accounting logic
// Read and write from appropriately added channels in the context to handle incoming and outgoing packets
async fn per_route_loop(
    ctx: DaemonContext,
    pipe: impl Pipe,
    their_fp: Option<Fingerprint>,
) -> anyhow::Result<()> {
    // create link service, call authenticate, get `their_public_key` from the AuthResponse
    let my_mux_sk = MuxSecret::generate();
    let mplex = Arc::new(Multiplex::new(my_mux_sk, None));
    mplex.add_pipe(pipe);

    let (send_outgoing, recv_outgoing) = smol::channel::bounded(1);
    let (send_incoming, recv_incoming) = smol::channel::bounded(1);
    let rpc = MultiplexRpcTransport::new(mplex.clone());
    let link = LinkClient::from(rpc);
    let resp = link
        .authenticate()
        .await
        .context("did not respond to authenticate")?;
    resp.verify(&mplex.peer_pk().context("could not obtain peer_pk")?)
        .context("did not authenticated correctly")?;

    let neighbor_idpk = resp.full_pk;

    // TODO: is this correct? they should be the same anyways (we should error if not)
    let their_fp = if let Some(fp) = their_fp {
        fp
    } else {
        neighbor_idpk.fingerprint()
    };

    let link_client = Arc::new(link);
    let _gossip = Immortal::respawn(
        RespawnStrategy::Immediate,
        clone!([ctx], move || gossip_loop(
            ctx.clone(),
            neighbor_idpk,
            link_client.clone(),
        )
        .map_err(log_error("gossip"))),
    );

    // TODO: debt accounting

    let task = Arc::new(Immortal::spawn(
        connection_loop(ctx, mplex.clone(), send_incoming, recv_outgoing, their_fp)
            .unwrap_or_else(|e| panic!("connection_loop died with {:?}", e)),
    ));
    todo!()
}

/// Loop that handles the control protocol
async fn control_protocol_loop(ctx: DaemonContext) -> anyhow::Result<()> {
    let http = HttpRpcServer::bind(ctx.init().control_listen).await?;
    let service = ControlService(ControlProtocolImpl::new(ctx));
    http.run(service).await?;
    Ok(())
}

/// Loop that listens to and handles incoming GlobalRpc requests
async fn global_rpc_loop(ctx: DaemonContext) -> anyhow::Result<()> {
    let socket = Arc::new(N2rSocket::bind(
        ctx.clone(),
        *ctx.get(GLOBAL_IDENTITY),
        Some(GLOBAL_RPC_DOCK),
    ));
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
            log::trace!("received forward msg, from {}, to {}", src_ep, dest_ep);

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
                log::warn!("haven {} is not registered with me!", dest_ep.fingerprint);
            }
        };
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
