use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use earendil_crypt::{
    ClientId, HavenFingerprint, HavenIdentitySecret, RelayFingerprint, RelayIdentitySecret,
};
use earendil_packet::Dock;
use itertools::Itertools;
use moka::sync::Cache;
use nanorpc::RpcTransport;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use smol_timeout::TimeoutExt;
use thiserror::Error;

use crate::{
    context::{DEBTS, MY_RELAY_IDENTITY, RELAY_GRAPH, SETTLEMENTS},
    network::all_client_neighs,
};
use crate::{
    control_protocol::{
        ChatError, ControlProtocol, DhtError, GlobalRpcArgs, GlobalRpcError, SendMessageArgs,
    },
    daemon::DaemonContext,
    global_rpc::transport::GlobalRpcTransport,
    haven_util::HavenLocator,
    network::{all_relay_neighs, is_relay_neigh},
    socket::{RelayEndpoint, Socket, SocketRecvError, SocketSendError},
};

use super::dht::{dht_get, dht_insert};

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
    async fn bind_n2r(&self, _socket_id: String, _anon_id: Option<String>, _dock: Option<Dock>) {
        todo!();
        // let anon_id = anon_id
        //     .map(|id| self.anon_identities.lock().get(&id))
        //     .unwrap_or_else(|| *self.ctx.get(GLOBAL_IDENTITY));
        // let socket = Socket::bind_n2r_internal(self.ctx.clone(), anon_id, dock);
        // self.sockets.insert(socket_id, socket);
    }

    async fn bind_haven(
        &self,
        socket_id: String,
        _anon_id: Option<String>,
        dock: Option<Dock>,
        rendezvous_point: Option<RelayFingerprint>,
    ) {
        let isk = HavenIdentitySecret::generate();
        let socket =
            Socket::bind_haven_internal(self.ctx.clone(), isk, dock, rendezvous_point).unwrap();
        self.sockets.insert(socket_id, socket);
    }

    async fn skt_info(&self, _skt_id: String) -> Result<RelayEndpoint, ControlProtErr> {
        todo!();
        // if let Some(skt) = self.sockets.get(&skt_id) {
        //     Ok(skt.local_endpoint())
        // } else {
        //     Err(ControlProtErr::NoSocket)
        // }
    }

    async fn havens_info(&self) -> Vec<(String, String)> {
        self.ctx
            .init()
            .havens
            .iter()
            .map(|haven_cfg| {
                let fp = haven_cfg
                    .identity
                    .actualize_haven()
                    .unwrap()
                    .public()
                    .fingerprint();
                match haven_cfg.handler {
                    crate::config::ForwardHandler::UdpService {
                        listen_dock,
                        upstream: _,
                    } => (
                        "UdpService".to_string(),
                        fp.to_string() + ":" + &listen_dock.to_string(),
                    ),
                    crate::config::ForwardHandler::TcpService {
                        listen_dock,
                        upstream: _,
                    } => (
                        "TcpService".to_string(),
                        fp.to_string() + ":" + &listen_dock.to_string(),
                    ),
                    crate::config::ForwardHandler::SimpleProxy { listen_dock } => (
                        "SimpleProxy".to_string(),
                        fp.to_string() + ":" + &listen_dock.to_string(),
                    ),
                }
            })
            .collect()
    }

    async fn send_message(&self, _args: SendMessageArgs) -> Result<(), ControlProtErr> {

        todo!();
        // if let Some(socket) = self.sockets.get(&args.socket_id) {
        //     socket.send_to(args.content, args.destination).await?;
        //     Ok(())
        // } else {
        //     Err(ControlProtErr::NoSocket)
        // }
    }

    async fn recv_message(
        &self,
        _socket_id: String,
    ) -> Result<(Bytes, RelayEndpoint), ControlProtErr> {
        todo!();
        // if let Some(socket) = self.sockets.get(&socket_id) {
        //     let recvd = socket.recv_from_haven().await?;
        //     Ok(recvd)
        // } else {
        //     Err(ControlProtErr::NoSocket)
        // }
    }

    async fn my_routes(&self) -> serde_json::Value {
        let lala: BTreeMap<String, serde_json::Value> = self
            .ctx
            .init()
            .in_routes
            .iter()
            .map(|(k, v)| todo!())
            .collect();
        serde_json::to_value(lala).unwrap()
    }

    async fn graph_dump(&self, human: bool) -> String {
        let my_fp = self
            .ctx
            .get(MY_RELAY_IDENTITY)
            .map(|id| id.public().fingerprint().to_string())
            .unwrap_or("node is not a relay".to_string());
        let relay_or_client = if self.ctx.init().in_routes.is_empty() {
            "oval"
        } else {
            "rect"
        };
        if human {
            let clients = all_client_neighs(&self.ctx)
                .iter()
                .fold(String::new(), |acc, neigh| {
                    let fp = neigh;
                    acc + &format!(
                        "\n{:?}\nnet debt: {:?}\n",
                        fp.to_string(),
                        self.ctx.get(DEBTS).client_net_debt_est(fp)
                    )
                });
            let relays = all_relay_neighs(&self.ctx)
                .iter()
                .fold(String::new(), |acc, neigh| {
                    let fp = neigh;
                    acc + &format!(
                        "\n{:?}\nnet debt: {:?}\n",
                        fp.to_string(),
                        self.ctx.get(DEBTS).relay_net_debt_est(fp)
                    )
                });
            let all_adjs = self
                .ctx
                .get(RELAY_GRAPH)
                .read()
                .all_adjacencies()
                .sorted_by(|a, b| Ord::cmp(&a.left, &b.left))
                .fold(String::new(), |acc, adj| {
                    acc + &format!(
                        "{:?} -- {:?}\n",
                        adj.left.to_string(),
                        adj.right.to_string()
                    )
                });
            format!(
                "My fingerprint:\n{}\t[{}]\n\nMy neighbors:{}\n{}\nRelay graph:\n{}",
                my_fp, relay_or_client, clients, relays, all_adjs
            )
        } else {
            let all_adjs = self
                .ctx
                .get(RELAY_GRAPH)
                .read()
                .all_adjacencies()
                .sorted_by(|a, b| Ord::cmp(&a.left, &b.left))
                .fold(String::new(), |acc, adj| {
                    acc + &format!(
                        "{:?} -- {:?};\n",
                        adj.left.to_string(),
                        adj.right.to_string()
                    )
                });
            let all_nodes: String =
                self.ctx
                    .get(RELAY_GRAPH)
                    .read()
                    .all_nodes()
                    .fold(String::new(), |acc, node| {
                        let node_str = node.to_string();
                        let _desc = self.ctx.get(RELAY_GRAPH).read().identity(&node).unwrap();
                        acc + &format!(
                            "{:?} [label={:?}, shape={}]\n",
                            node_str,
                            get_node_label(&node),
                            "oval".to_string()
                                + (if is_relay_neigh(&self.ctx, node) {
                                    ", color=lightpink,style=filled"
                                } else {
                                    ""
                                })
                        )
                    });
            format!(
                "graph G {{
                    rankdir=\"LR\"
                    {:?} [shape={},color=lightblue,style=filled]
                {}
                {}
            }}",
                my_fp, relay_or_client, all_nodes, all_adjs
            )
        }
    }

    #[tracing::instrument(skip(self))]
    async fn send_global_rpc(
        &self,
        send_args: GlobalRpcArgs,
    ) -> Result<serde_json::Value, GlobalRpcError> {
        let client = GlobalRpcTransport::new(self.ctx.clone(), send_args.destination);
        let res = if let Some(res) = client
            .call(&send_args.method, &send_args.args)
            .await
            .map_err(|e| {
                tracing::warn!("send_global_rpc transport failed with {:?}", e);
                GlobalRpcError::SendError
            })? {
            res.map_err(|e| {
                tracing::warn!("send_global_rpc remote failed with {:?}", e);
                GlobalRpcError::SendError
            })?
        } else {
            return Err(GlobalRpcError::SendError);
        };
        Ok(res)
    }

    async fn insert_rendezvous(&self, locator: HavenLocator) -> Result<(), DhtError> {
        dht_insert(&self.ctx, locator).await;
        Ok(())
    }

    async fn get_rendezvous(
        &self,
        fingerprint: HavenFingerprint,
    ) -> Result<Option<HavenLocator>, DhtError> {
        dht_get(&self.ctx, fingerprint)
            .timeout(Duration::from_secs(30))
            .await
            .map_or(
                Err(DhtError::NetworkFailure(
                    "dht_get({key}) timed out".to_owned(),
                )),
                |res| res,
            )
    }

    async fn list_clients(&self) -> Vec<ClientId> {
        todo!();
        // chat::list_clients(&self.ctx)
    }

    async fn list_relays(&self) -> Vec<RelayFingerprint> {
        todo!();
        // chat::list_relays(&self.ctx)
    }

    async fn list_chats(&self) -> String {
        todo!();
        // chat::list_chats(&self.ctx)
    }

    async fn get_client_chat(&self, neigh: ClientId) -> Vec<(bool, String, SystemTime)> {
        todo!();
        // chat::get_client_chat(&self.ctx, neigh)
    }

    async fn get_relay_chat(&self, neigh: RelayFingerprint) -> Vec<(bool, String, SystemTime)> {
        todo!();
        // chat::get_relay_chat(&self.ctx, neigh)
    }

    async fn send_client_chat_msg(&self, dest: ClientId, msg: String) -> Result<(), ChatError> {
        todo!();
        // chat::send_client_chat_msg(&self.ctx, dest, msg)
        //     .await
        //     .map_err(|e| ChatError::Send(e.to_string()))
    }

    async fn send_relay_chat_msg(
        &self,
        dest: RelayFingerprint,
        msg: String,
    ) -> Result<(), ChatError> {
        todo!();
        // chat::send_relay_chat_msg(&self.ctx, dest, msg)
        //     .await
        //     .map_err(|e| ChatError::Send(e.to_string()))
    }

    async fn list_debts(&self) -> Vec<String> {
        self.ctx.get(DEBTS).list()
    }

    async fn list_settlements(&self) -> Vec<String> {
        self.ctx.get(SETTLEMENTS).list()
    }
}

fn get_node_label(fp: &RelayFingerprint) -> String {
    let node = fp.to_string();
    format!("{}..{}", &node[..4], &node[node.len() - 4..node.len()])
}

struct AnonIdentities {
    map: Cache<String, RelayIdentitySecret>,
}

impl AnonIdentities {
    pub fn new() -> Self {
        let map = Cache::builder()
            .max_capacity(100_000)
            .time_to_idle(Duration::from_secs(3600))
            .build();
        Self { map }
    }

    pub fn get(&mut self, id: &str) -> RelayIdentitySecret {
        let pseudo_secret = blake3::hash(id.as_bytes());
        self.map.get_with_by_ref(id, || {
            RelayIdentitySecret::from_bytes(pseudo_secret.as_bytes())
        })
    }
}

#[derive(Error, Serialize, Deserialize, Debug)]
pub enum ControlProtErr {
    #[error(transparent)]
    SocketSendError(#[from] SocketSendError),
    #[error(transparent)]
    SocketRecvError(#[from] SocketRecvError),
    #[error(
        "No socket exists for this socket_id! Bind a socket to this id before trying to use it ^_^"
    )]
    NoSocket,
}
