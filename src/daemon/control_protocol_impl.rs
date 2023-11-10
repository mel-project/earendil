use std::{collections::BTreeMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use earendil_crypt::{Fingerprint, IdentitySecret};
use earendil_packet::Dock;
use moka::sync::Cache;
use nanorpc::RpcTransport;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sosistab2::ObfsUdpSecret;
use thiserror::Error;

use crate::{
    config::{InRouteConfig, OutRouteConfig},
    control_protocol::{ControlProtocol, DhtError, GlobalRpcArgs, GlobalRpcError, SendMessageArgs},
    daemon::DaemonContext,
};

use super::{
    global_rpc::transport::GlobalRpcTransport,
    haven::HavenLocator,
    n2r_socket::Endpoint,
    socket::{Socket, SocketRecvError, SocketSendError},
};

pub struct ControlProtocolImpl {
    anon_identities: Arc<Mutex<AnonIdentities>>,
    sockets: DashMap<String, Socket>,
    ctx: DaemonContext,
}

impl ControlProtocolImpl {
    pub fn new(ctx: DaemonContext) -> Self {
        Self {
            ctx,
            sockets: DashMap::new(),
            anon_identities: Arc::new(Mutex::new(AnonIdentities::new())),
        }
    }
}

#[async_trait]
impl ControlProtocol for ControlProtocolImpl {
    async fn bind_n2r(&self, socket_id: String, anon_id: Option<String>, dock: Option<Dock>) {
        let anon_id = anon_id.map(|id| self.anon_identities.lock().get(&id));
        let socket = Socket::bind_n2r(&self.ctx, anon_id.clone(), dock);
        self.sockets.insert(socket_id, socket);

        if let Some(aid) = anon_id {
            log::info!(
                "----------- Bound N2rSocket with ANOOOON FINGERPRING: {} ----------",
                aid.public().fingerprint()
            );
        }
    }

    async fn bind_haven(
        &self,
        socket_id: String,
        anon_id: Option<String>,
        dock: Option<Dock>,
        rendezvous_point: Option<Fingerprint>,
    ) {
        let anon_id = anon_id.map(|id| self.anon_identities.lock().get(&id));
        let socket = Socket::bind_haven(&self.ctx, anon_id.clone(), dock, rendezvous_point);
        self.sockets.insert(socket_id, socket);

        if let Some(aid) = anon_id.clone() {
            log::info!(
                "----------- Bound HavenSocket with ANOOOON FINGERPRING: {} ----------",
                aid.public().fingerprint()
            );
        }
    }

    async fn send_message(&self, args: SendMessageArgs) -> Result<(), ControlProtSendErr> {
        if let Some(socket) = self.sockets.get(&args.socket_id) {
            socket.send_to(args.content, args.destination).await?;
            Ok(())
        } else {
            Err(ControlProtSendErr::NoSocket)
        }
    }

    async fn recv_message(
        &self,
        socket_id: String,
    ) -> Result<(Bytes, Endpoint), ControlProtRecvErr> {
        if let Some(socket) = self.sockets.get(&socket_id) {
            let recvd = socket.recv_from().await?;
            Ok(recvd)
        } else {
            Err(ControlProtRecvErr::NoSocket)
        }
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

    async fn send_global_rpc(
        &self,
        send_args: GlobalRpcArgs,
    ) -> Result<serde_json::Value, GlobalRpcError> {
        let client = GlobalRpcTransport::new(
            self.ctx.clone(),
            Some(IdentitySecret::generate()),
            send_args.destination,
        );
        let res = if let Some(res) = client
            .call(&send_args.method, &send_args.args)
            .await
            .map_err(|_| GlobalRpcError::SendError)?
        {
            res.map_err(|_| GlobalRpcError::SendError)?
        } else {
            return Err(GlobalRpcError::SendError);
        };

        Ok(res)
    }

    async fn insert_rendezvous(&self, locator: HavenLocator) -> Result<(), DhtError> {
        self.ctx.dht_insert(locator).await;
        Ok(())
    }

    async fn get_rendezvous(
        &self,
        fingerprint: Fingerprint,
    ) -> Result<Option<HavenLocator>, DhtError> {
        self.ctx.dht_get(fingerprint).await
    }
}

struct AnonIdentities {
    map: Cache<String, IdentitySecret>,
}

impl AnonIdentities {
    pub fn new() -> Self {
        let map = Cache::builder()
            .max_capacity(100_000)
            .time_to_idle(Duration::from_secs(3600))
            .build();
        Self { map }
    }

    pub fn get(&mut self, id: &str) -> IdentitySecret {
        self.map.get_with_by_ref(id, IdentitySecret::generate)
    }
}

#[derive(Error, Serialize, Deserialize, Debug)]
pub enum ControlProtSendErr {
    #[error(transparent)]
    SocketSendError(#[from] SocketSendError),
    #[error(
        "No socket exists for this socket_id! Bind a socket to this id before trying to use it ^_^"
    )]
    NoSocket,
}

#[derive(Error, Serialize, Deserialize, Debug)]
pub enum ControlProtRecvErr {
    #[error(transparent)]
    SocketRecvError(#[from] SocketRecvError),
    #[error(
        "No socket exists for this socket_id! Bind a socket to this id before trying to use it ^_^"
    )]
    NoSocket,
}
