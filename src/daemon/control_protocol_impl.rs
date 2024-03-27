use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;

use earendil_crypt::{
    AnonEndpoint, ClientId, HavenFingerprint, RelayFingerprint, RelayIdentitySecret,
};
use either::Either;
use itertools::Itertools;
use moka::sync::Cache;
use nanorpc::RpcTransport;
use parking_lot::Mutex;

use smol_timeout::TimeoutExt;

use crate::{
    context::{MY_RELAY_IDENTITY, RELAY_GRAPH},
    dht::{dht_get, dht_insert},
    haven::HavenLocator,
    n2r_socket::N2rClientSocket,
};
use crate::{
    control_protocol::{ChatError, ControlProtocol, DhtError, GlobalRpcArgs, GlobalRpcError},
    daemon::DaemonContext,
    global_rpc::transport::GlobalRpcTransport,
    network::is_relay_neigh,
};

use super::chat::{ChatEntry, CHATS};

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
            .map(|(_k, _v)| todo!())
            .collect();
        serde_json::to_value(lala).unwrap()
    }

    async fn relay_graphviz(&self) -> String {
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

    async fn list_chats(&self) -> String {
        self.ctx.get(CHATS).list_chats()
    }

    async fn get_chat(&self, neigh: String) -> Result<Vec<(bool, String, SystemTime)>, ChatError> {
        let neighbor = if let Ok(client) = neigh.parse::<ClientId>() {
            Either::Left(client)
        } else if let Ok(relay) = neigh.parse::<RelayFingerprint>() {
            Either::Right(relay)
        } else {
            return Err(ChatError::Get("unrecognized neighbor".into()));
        };

        let convo = self.ctx.get(CHATS).dump_convo(neighbor);
        Ok(convo
            .into_iter()
            .map(|entry| (entry.is_incoming, entry.text, entry.time))
            .collect())
    }

    async fn send_chat(&self, dest: String, msg: String) -> Result<(), ChatError> {
        let neigh = if let Ok(client) = dest.parse::<ClientId>() {
            Either::Left(client)
        } else if let Ok(relay) = dest.parse::<RelayFingerprint>() {
            Either::Right(relay)
        } else {
            return Err(ChatError::Send("unrecognized neighbor".into()));
        };

        let entry = ChatEntry::new_outgoing(msg);
        self.ctx.get(CHATS).record(neigh, entry);
        Ok(())
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
