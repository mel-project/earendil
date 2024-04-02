mod control_protocol_impl;

mod inout_route;
mod link;
mod serve_haven;
mod socks5;
use async_trait::async_trait;
use bytes::Bytes;
use clone_macro::clone;
use earendil_crypt::{AnonEndpoint, ClientId, RelayFingerprint, RelayIdentitySecret};
use earendil_packet::ForwardInstruction;

use earendil_topology::{IdentityDescriptor, RelayGraph};
use futures_util::{stream::FuturesUnordered, StreamExt, TryFutureExt};
use nanorpc::{JrpcRequest, JrpcResponse, RpcService, RpcTransport};
use nanorpc_http::server::HttpRpcServer;

use nursery_macro::nursery;
use smol::Task;
use smolscale::immortal::{Immortal, RespawnStrategy};
mod chat;
use stdcode::StdcodeSerializeExt;
use tracing::instrument;

use std::convert::Infallible;
use std::{sync::Arc, time::Duration};

use crate::daemon::chat::CHATS;
use crate::{
    context::MY_CLIENT_ID,
    daemon::inout_route::{dial_out_route, listen_in_route},
    haven::rendezvous_forward_loop,
    n2r_socket::{n2r_socket_shuttle, N2rClientSocket},
};
use crate::{context::MY_RELAY_IDENTITY, n2r_socket::N2rRelaySocket};

use crate::control_protocol::ControlClient;
use crate::db::db_write;

use crate::control_protocol::ControlService;
use crate::log_error;

use crate::{
    config::ConfigFile,
    context::{MY_RELAY_ONION_SK, RELAY_GRAPH},
    global_rpc::GLOBAL_RPC_DOCK,
};
use crate::{context::DaemonContext, global_rpc::server::GlobalRpcImpl};
use crate::{control_protocol::SendMessageError, global_rpc::GlobalRpcService};

pub use self::chat::ChatEntry;
use self::control_protocol_impl::ControlProtocolImpl;

pub struct Daemon {
    pub(crate) ctx: DaemonContext,
    _task: Task<anyhow::Result<()>>,
}

impl Daemon {
    /// Initializes the daemon and starts all background loops
    pub fn init(config: ConfigFile) -> anyhow::Result<Daemon> {
        let ctx = DaemonContext::new(config);

        tracing::info!("starting background task for main_daemon");
        let task = smolscale::spawn(main_daemon(ctx.clone()));
        Ok(Self { ctx, _task: task })
    }

    pub fn is_client(&self) -> bool {
        self.ctx.init().in_routes.is_empty()
    }

    pub fn identity(&self) -> Option<RelayIdentitySecret> {
        *self.ctx.get(MY_RELAY_IDENTITY)
    }

    pub fn client_id(&self) -> ClientId {
        *self.ctx.get(MY_CLIENT_ID)
    }

    pub fn control_client(&self) -> ControlClient {
        ControlClient::from(DummyControlProtocolTransport {
            inner: ControlService(ControlProtocolImpl::new(self.ctx.clone())),
        })
    }

    pub async fn wait_until_dead(self) -> anyhow::Error {
        self._task.await.unwrap_err()
    }

    pub fn ctx(&self) -> DaemonContext {
        self.ctx.clone()
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

#[tracing::instrument(skip_all, fields(client_id=ctx.get(MY_CLIENT_ID), relay_fp=debug(ctx.get(MY_RELAY_IDENTITY).map(|id| id.public().fingerprint().to_string()[..6].to_string()))))]
pub async fn main_daemon(ctx: DaemonContext) -> anyhow::Result<()> {
    let is_client = ctx.init().is_client();

    scopeguard::defer!(tracing::info!(is_client, "daemon is now DROPPED!"));

    // Run the loops
    let _relay_loops = if !is_client {
        tracing::info!(
            "daemon starting with fingerprint {:?}",
            ctx.get(MY_RELAY_IDENTITY)
                .expect("only relays have global identities")
                .public()
                .fingerprint()
        );

        scopeguard::defer!({
            tracing::info!(
                "daemon with fingerprint {:?} is now DROPPED!",
                ctx.get(MY_RELAY_IDENTITY)
                    .expect("only relays have global identities")
                    .public()
                    .fingerprint()
            )
        });

        let identity_refresh_loop = Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([ctx], move || clone!([ctx], async move {
                tracing::trace!("WE ARE INSERTING OURSELVES");
                // first insert ourselves
                ctx.get(RELAY_GRAPH)
                    .write()
                    .insert_identity(IdentityDescriptor::new(
                        &ctx.get(MY_RELAY_IDENTITY)
                            .expect("only relays have global identities"),
                        ctx.get(MY_RELAY_ONION_SK),
                    ))?;
                smol::Timer::after(Duration::from_secs(60)).await;
                anyhow::Ok(())
            })),
        );

        let global_rpc_loop = Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([ctx], move || global_rpc_loop(ctx.clone())
                .map_err(log_error("global_rpc_loop"))),
        );

        let rendezvous_forward_loop = Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([ctx], move || rendezvous_forward_loop(ctx.clone())
                .map_err(log_error("rendezvous_forward_loop"))),
        );

        Some((
            identity_refresh_loop,
            global_rpc_loop,
            rendezvous_forward_loop,
        ))
    } else {
        None
    };

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

    let _n2r_shuttle_loop = Immortal::respawn(
        RespawnStrategy::Immediate,
        clone!([ctx], move || n2r_socket_shuttle(ctx.clone())
            .map_err(log_error("n2r_socket_shuttle"))),
    );

    if ctx.init().in_routes.is_empty() && ctx.init().out_routes.is_empty() {
        anyhow::bail!("must have routes to start daemon")
    }

    nursery!({
        let mut fallible_tasks = FuturesUnordered::new();

        // For every in_routes block, spawn a task to handle incoming stuff
        for (_in_route_name, config) in ctx.init().in_routes.iter() {
            fallible_tasks.push(spawn!(listen_in_route(&ctx, config)));
        }

        // For every out_routes block, spawn a task to handle outgoing stuff
        for (_out_route_name, config) in ctx.init().out_routes.iter() {
            fallible_tasks.push(spawn!(dial_out_route(&ctx, config)));
        }

        // For every haven, serve the haven
        for config in ctx.init().havens.iter() {
            fallible_tasks.push(spawn!(serve_haven::serve_haven(&ctx, config)));
        }

        if let Some(socks5_cfg) = ctx.init().socks5 {
            fallible_tasks.push(spawn!(socks5::socks5_loop(&ctx, socks5_cfg)));
        }

        // Join all the tasks. If any of the tasks terminate with an error, that's fatal!
        while let Some(next) = fallible_tasks.next().await {
            next?;
        }
        anyhow::Ok(())
    })
}

#[instrument(skip(ctx))]
/// Loop that handles the persistence of contex state
async fn db_sync_loop(ctx: DaemonContext) -> anyhow::Result<()> {
    loop {
        tracing::debug!("DBDBDBDB syncing DB...");
        let global_id = ctx.get(MY_RELAY_IDENTITY).stdcode();
        let graph = ctx.clone().get(RELAY_GRAPH).read().stdcode();
        let chats = ctx.get(CHATS).stdcode();

        db_write(&ctx, "global_identity", global_id).await?;
        db_write(&ctx, "relay_graph", graph).await?;
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
    let relay_skt = Arc::new(N2rRelaySocket::bind(ctx.clone(), Some(GLOBAL_RPC_DOCK))?);

    let my_anon_ep = AnonEndpoint::random();
    let n2r_skt = N2rClientSocket::bind(ctx.clone(), my_anon_ep)?;
    let service = Arc::new(GlobalRpcService(GlobalRpcImpl::new(ctx, n2r_skt)));
    nursery!(loop {
        let socket = relay_skt.clone();
        let (req, endpoint) = socket.recv_from().await?;
        tracing::debug!(endpoint = debug(endpoint), "incoming GlobalRpc server");
        let service = service.clone();
        spawn!(async move {
            let req: JrpcRequest = serde_json::from_str(&String::from_utf8(req.to_vec())?)?;
            tracing::debug!(
                endpoint = debug(endpoint),
                method = req.method,
                "incoming GlobalRpc call"
            );
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
    })
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
