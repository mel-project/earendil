use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use earendil_crypt::{ClientId, Fingerprint, IdentitySecret};
use earendil_packet::Dock;
use itertools::Itertools;
use moka::sync::Cache;
use nanorpc::RpcTransport;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use smol_timeout::TimeoutExt;
use sosistab2_obfsudp::ObfsUdpSecret;
use thiserror::Error;

use crate::{
    config::InRouteConfig,
    control_protocol::{
        ChatError, ControlProtocol, DhtError, GlobalRpcArgs, GlobalRpcError, SendMessageArgs,
    },
    daemon::{
        context::{CLIENT_TABLE, DEBTS, NEIGH_TABLE_NEW, RELAY_GRAPH},
        DaemonContext,
    },
    global_rpc::transport::GlobalRpcTransport,
    haven_util::HavenLocator,
    socket::{Endpoint, Socket, SocketRecvError, SocketSendError},
};

use super::{
    context::{GLOBAL_IDENTITY, SETTLEMENTS},
    dht::{dht_get, dht_insert},
    inout_route::chat,
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
        let anon_id = anon_id
            .map(|id| self.anon_identities.lock().get(&id))
            .unwrap_or_else(|| *self.ctx.get(GLOBAL_IDENTITY));
        let socket = Socket::bind_n2r_internal(self.ctx.clone(), anon_id, dock);
        self.sockets.insert(socket_id, socket);
    }

    async fn bind_haven(
        &self,
        socket_id: String,
        anon_id: Option<String>,
        dock: Option<Dock>,
        rendezvous_point: Option<Fingerprint>,
    ) {
        let isk = anon_id
            .map(|id| self.anon_identities.lock().get(&id))
            .unwrap_or_else(|| *self.ctx.get(GLOBAL_IDENTITY));
        let socket = Socket::bind_haven_internal(self.ctx.clone(), isk, dock, rendezvous_point);
        self.sockets.insert(socket_id, socket);
    }

    async fn skt_info(&self, skt_id: String) -> Result<Endpoint, ControlProtErr> {
        if let Some(skt) = self.sockets.get(&skt_id) {
            Ok(skt.local_endpoint())
        } else {
            Err(ControlProtErr::NoSocket)
        }
    }

    async fn havens_info(&self) -> Vec<(String, String)> {
        self.ctx
            .init()
            .havens
            .iter()
            .map(|haven_cfg| {
                let fp = haven_cfg
                    .identity
                    .actualize()
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

    async fn send_message(&self, args: SendMessageArgs) -> Result<(), ControlProtErr> {
        if let Some(socket) = self.sockets.get(&args.socket_id) {
            socket.send_to(args.content, args.destination).await?;
            Ok(())
        } else {
            Err(ControlProtErr::NoSocket)
        }
    }

    async fn recv_message(&self, socket_id: String) -> Result<(Bytes, Endpoint), ControlProtErr> {
        if let Some(socket) = self.sockets.get(&socket_id) {
            let recvd = socket.recv_from().await?;
            Ok(recvd)
        } else {
            Err(ControlProtErr::NoSocket)
        }
    }

    async fn my_routes(&self) -> serde_json::Value {
        let lala: BTreeMap<String, serde_json::Value> = self
            .ctx.init()
            .in_routes
            .iter()
            .map(|(k, v)| match v {
                InRouteConfig::Obfsudp { listen, secret, link_price } => {
                    let secret =
                        ObfsUdpSecret::from_bytes(*blake3::hash(secret.as_bytes()).as_bytes());
                    (
                        k.clone(),
                        json!( {
                            "fingerprint": format!("{}", self.ctx.get(GLOBAL_IDENTITY).public().fingerprint()),
                            "connect": format!("<YOUR_IP>:{}", listen.port()),
                            "cookie": hex::encode(secret.to_public().as_bytes()),
                            "link_price": link_price,
                        }),
                    )
                }
            })
            .collect();
        serde_json::to_value(lala).unwrap()
    }

    async fn graph_dump(&self, human: bool) -> String {
        let my_fp = self
            .ctx
            .get(GLOBAL_IDENTITY)
            .public()
            .fingerprint()
            .to_string();
        let relay_or_client = if self.ctx.init().in_routes.is_empty() {
            "oval"
        } else {
            "rect"
        };
        if human {
            let clients = self.ctx.get(CLIENT_TABLE).iter().map(|s| *s.0).fold(
                String::new(),
                |acc, neigh| {
                    let fp = neigh;
                    acc + &format!(
                        "\n{:?}\nnet debt: {:?}\n",
                        fp.to_string(),
                        self.ctx.get(DEBTS).client_net_debt_est(&fp)
                    )
                },
            );
            let relays = self.ctx.get(NEIGH_TABLE_NEW).iter().map(|s| *s.0).fold(
                String::new(),
                |acc, neigh| {
                    let fp = neigh;
                    acc + &format!(
                        "\n{:?}\nnet debt: {:?}\n",
                        fp.to_string(),
                        self.ctx.get(DEBTS).relay_net_debt_est(&fp)
                    )
                },
            );
            let all_adjs = self
                .ctx
                .get(RELAY_GRAPH)
                .read()
                .all_adjacencies()
                .filter(|adj| {
                    // only display relays
                    self.ctx
                        .get(RELAY_GRAPH)
                        .read()
                        .identity(&adj.left)
                        .map_or(false, |id| id.is_relay)
                        && self
                            .ctx
                            .get(RELAY_GRAPH)
                            .read()
                            .identity(&adj.right)
                            .map_or(false, |id| id.is_relay)
                })
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
                        let desc = self.ctx.get(RELAY_GRAPH).read().identity(&node).unwrap();
                        acc + &format!(
                            "{:?} [label={:?}, shape={}]\n",
                            node_str,
                            get_node_label(&node),
                            (if desc.is_relay { "oval" } else { "rect" }).to_string()
                                + (if self.ctx.get(NEIGH_TABLE_NEW).contains_key(&node) {
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
        let client = GlobalRpcTransport::new(
            self.ctx.clone(),
            IdentitySecret::generate(),
            send_args.destination,
        );
        let res = if let Some(res) = client
            .call(&send_args.method, &send_args.args)
            .await
            .map_err(|e| {
                tracing::warn!("send_global_rpc failed with {:?}", e);
                GlobalRpcError::SendError
            })? {
            res.map_err(|e| {
                tracing::warn!("send_global_rpc failed with {:?}", e);
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
        fingerprint: Fingerprint,
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
        chat::list_clients(&self.ctx)
    }

    async fn list_relays(&self) -> Vec<Fingerprint> {
        chat::list_relays(&self.ctx)
    }

    async fn list_chats(&self) -> String {
        chat::list_chats(&self.ctx)
    }

    async fn get_client_chat(&self, neigh: ClientId) -> Vec<(bool, String, SystemTime)> {
        chat::get_client_chat(&self.ctx, neigh)
    }

    async fn get_relay_chat(&self, neigh: Fingerprint) -> Vec<(bool, String, SystemTime)> {
        chat::get_relay_chat(&self.ctx, neigh)
    }

    async fn send_client_chat_msg(&self, dest: ClientId, msg: String) -> Result<(), ChatError> {
        chat::send_client_chat_msg(&self.ctx, dest, msg)
            .await
            .map_err(|e| ChatError::Send(e.to_string()))
    }

    async fn send_relay_chat_msg(&self, dest: Fingerprint, msg: String) -> Result<(), ChatError> {
        chat::send_relay_chat_msg(&self.ctx, dest, msg)
            .await
            .map_err(|e| ChatError::Send(e.to_string()))
    }

    async fn list_debts(&self) -> Vec<String> {
        self.ctx.get(DEBTS).list()
    }

    async fn list_settlements(&self) -> Vec<String> {
        self.ctx.get(SETTLEMENTS).list()
    }
}

fn get_node_label(fp: &Fingerprint) -> String {
    let node = fp.to_string();
    format!("{}..{}", &node[..4], &node[node.len() - 4..node.len()])
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
        let pseudo_secret = blake3::hash(id.as_bytes());
        self.map
            .get_with_by_ref(id, || IdentitySecret::from_bytes(pseudo_secret.as_bytes()))
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
