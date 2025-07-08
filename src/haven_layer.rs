mod bicache;
mod dht;
mod global_rpc;
mod packet_conn;
mod pooled;
mod stream;
mod vrh;

use std::sync::Arc;

use bytes::Bytes;
use clone_macro::clone;
use dht::{dht_get, dht_insert};
use earendil_crypt::{
    AnonEndpoint, HavenEndpoint, HavenFingerprint, HavenIdentitySecret, RelayFingerprint,
};

use futures::TryFutureExt;
use global_rpc::GlobalRpcTransport;
use nanorpc::{JrpcRequest, RpcService};
use smolscale::immortal::{Immortal, RespawnStrategy};
use stdcode::StdcodeSerializeExt;

use crate::{
    anon_layer::AnonLayer,
    haven_layer::vrh::{H2rMessage, R2hMessage},
    transport_layer::TransportLayer,
};

pub use self::packet_conn::HavenListener;
pub use self::packet_conn::HavenPacketConn;
pub use self::pooled::PooledListener;
pub use self::pooled::PooledVisitor;
use self::{
    bicache::Bicache,
    global_rpc::{GLOBAL_RPC_DOCK, GlobalRpcImpl, GlobalRpcService},
    vrh::V2rMessage,
};
pub use dht::HavenLocator;

const HAVEN_FORWARD_DOCK: u32 = 100002;

pub struct HavenLayer {
    ctx: HavenLayerCtx,
    _rpc_server: Immortal,
    _rendezvous_forward: Immortal,
}

impl HavenLayer {
    pub fn new(anon: AnonLayer, cfg: HavenLayerConfig) -> Self {
        let ctx = HavenLayerCtx {
            anon: anon.into(),
            registered_havens: Bicache::new(1000).into(),
        };

        let rpc_server = Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([ctx], move || serve_rpc(ctx.clone()).inspect_err(
                |e| tracing::error!(err = debug(e), "GlobalRPC serving restarted")
            )),
        );
        let rendezvous_forward = Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([ctx], move || rendezvous_forward(ctx.clone()).inspect_err(
                |e| tracing::error!(err = debug(e), "rendezvous forwarding restarted")
            )),
        );
        Self {
            ctx,
            _rpc_server: rpc_server,
            _rendezvous_forward: rendezvous_forward,
        }
    }

    /// Creates a low-level, unreliable packet connection.
    pub async fn packet_connect(&self, dest: HavenEndpoint) -> anyhow::Result<HavenPacketConn> {
        let conn = HavenPacketConn::connect(&self.ctx, dest).await?;
        Ok(conn)
    }

    /// Creates a low-level, unreliable packet listener.
    pub async fn packet_listen(
        &self,
        identity: HavenIdentitySecret,
        port: u16,
        rendezvous: RelayFingerprint,
    ) -> anyhow::Result<HavenListener> {
        let conn = HavenListener::bind(&self.ctx, identity, port, rendezvous).await?;
        Ok(conn)
    }

    /// Creates a new pooled visitor. Under Earendil's anonymity model, each visitor should be unlinkable to any other visitor, but streams created within each visitor are linkable to the same haven each other by the haven (though not by the network).
    pub async fn pooled_visitor(&self) -> PooledVisitor {
        PooledVisitor::new(self.ctx.clone())
    }

    /// Creates a new pooled listener.
    pub async fn pooled_listen(
        &self,
        identity: HavenIdentitySecret,
        port: u16,
        rendezvous: RelayFingerprint,
    ) -> anyhow::Result<PooledListener> {
        Ok(PooledListener::new(
            self.packet_listen(identity, port, rendezvous).await?,
        ))
    }

    pub fn transport_layer(&self) -> &TransportLayer {
        self.ctx.anon.transport_layer()
    }

    pub fn grpc_transport(&self, dest: RelayFingerprint) -> GlobalRpcTransport {
        GlobalRpcTransport::new(dest, self.ctx.anon.bind_anon())
    }

    pub async fn dht_get(
        &self,
        fingerprint: HavenFingerprint,
    ) -> anyhow::Result<Option<HavenLocator>> {
        dht_get(&self.ctx, fingerprint).await
    }

    pub async fn dht_insert(&self, locator: HavenLocator) {
        dht_insert(&self.ctx, locator).await
    }
}

async fn rendezvous_forward(ctx: HavenLayerCtx) -> anyhow::Result<()> {
    let socket = ctx.anon.bind_relay(HAVEN_FORWARD_DOCK);

    loop {
        if let Ok((msg, src_ep)) = socket.recv_from().await {
            let ctx = ctx.clone();
            let src_is_visitor = ctx.registered_havens.get_by_key(&src_ep).is_none();
            if src_is_visitor {
                let inner: V2rMessage = stdcode::deserialize(&msg)?;

                if let Some(haven_anon_ep) = ctx
                    .registered_havens
                    .get_by_value(&inner.dest_haven.fingerprint)
                {
                    tracing::trace!(
                        src_ep = debug(src_ep),
                        haven_anon_ep = debug(haven_anon_ep),
                        "received V2R msg"
                    );

                    let body: Bytes = R2hMessage {
                        src_visitor: src_ep,

                        payload: inner.payload,
                    }
                    .stdcode()
                    .into();

                    tracing::trace!(haven_anon_ep = debug(haven_anon_ep), "sending R2H");
                    socket.send_to(body, haven_anon_ep).await?;
                } else {
                    tracing::warn!(
                        "haven {} is not registered with me!",
                        inner.dest_haven.fingerprint
                    );
                }
            } else {
                // src is haven
                let inner: H2rMessage = stdcode::deserialize(&msg)?;
                tracing::trace!(
                    src_ep = debug(src_ep),
                    dest_visitor = debug(inner.dest_visitor),
                    len = msg.len(),
                    "received H2R msg",
                );
                let body: Bytes = inner.payload.stdcode().into();
                tracing::trace!(dest_visitor = debug(inner.dest_visitor), "sending bare");
                socket.send_to(body, inner.dest_visitor).await?;
            }
        };
    }
}

async fn serve_rpc(ctx: HavenLayerCtx) -> anyhow::Result<()> {
    let rpc_socket = ctx.anon.bind_relay(GLOBAL_RPC_DOCK);
    let service = GlobalRpcService(GlobalRpcImpl::new(ctx.clone()));
    loop {
        let (bts, from) = rpc_socket.recv_from().await?;
        // TODO this is not concurrent, but it is fine since nothing takes too long
        let fallible = async {
            let req: JrpcRequest = serde_json::from_slice(&bts)?;
            // println!("req = {:?}", req);
            let res = service.respond_raw(req.clone()).await;
            // println!("resp = {:?}", res);
            let body = serde_json::to_vec(&res)?.into();
            rpc_socket.send_to(body, from).await?;
            // println!("successfully sent rpc response");
            anyhow::Ok(())
        };
        if let Err(err) = fallible.await {
            tracing::debug!(err = debug(err), "error serving RPC");
        }
    }
}

#[derive(Clone)]
struct HavenLayerCtx {
    anon: Arc<AnonLayer>,
    registered_havens: Arc<Bicache<AnonEndpoint, HavenFingerprint>>,
}

pub struct HavenLayerConfig {
    pub is_relay: bool,
}
