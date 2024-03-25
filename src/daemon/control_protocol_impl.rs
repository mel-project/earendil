use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;

use earendil_crypt::{
    AnonEndpoint, ClientId, HavenFingerprint, RelayFingerprint, RelayIdentitySecret,
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
    dht::{dht_get, dht_insert},
    haven::HavenLocator,
    n2r_socket::N2rClientSocket,
    network::all_client_neighs,
};
use crate::{
    control_protocol::{ChatError, ControlProtocol, DhtError, GlobalRpcArgs, GlobalRpcError},
    daemon::DaemonContext,
    global_rpc::transport::GlobalRpcTransport,
    network::{all_relay_neighs, is_relay_neigh},
};

pub struct ControlProtocolImpl {
    anon_identities: Arc<Mutex<AnonIdentities>>,

    ctx: DaemonContext,
}

impl ControlProtocolImpl {
    pub fn new(ctx: DaemonContext) -> Self {
        Self {
            ctx,

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
        todo!()
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
                    crate::config::HavenHandler::TcpService { upstream: _ } => (
                        "TcpService".to_string(),
                        fp.to_string() + ":" + &haven_cfg.listen_port.to_string(),
                    ),
                    crate::config::HavenHandler::SimpleProxy => (
                        "SimpleProxy".to_string(),
                        fp.to_string() + ":" + &haven_cfg.listen_port.to_string(),
                    ),
                }
            })
            .collect()
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
        let n2r_skt = N2rClientSocket::bind(self.ctx.clone(), AnonEndpoint::new())
            .expect("failed to bind n2r socket");
        let client = GlobalRpcTransport::new(self.ctx.clone(), send_args.destination, n2r_skt);
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
        let n2r_skt = N2rClientSocket::bind(self.ctx.clone(), AnonEndpoint::new())
            .expect("failed to bind n2r client socket");
        dht_insert(&self.ctx, locator, &n2r_skt).await;
        Ok(())
    }

    async fn get_rendezvous(
        &self,
        fingerprint: HavenFingerprint,
    ) -> Result<Option<HavenLocator>, DhtError> {
        let n2r_skt = N2rClientSocket::bind(self.ctx.clone(), AnonEndpoint::new())
            .expect("failed to bind n2r client socket");
        dht_get(&self.ctx, fingerprint, &n2r_skt)
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
