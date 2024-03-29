use std::{
    collections::{BTreeMap, HashMap},
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

use smol_timeout::TimeoutExt;

use crate::{
    context::{MY_CLIENT_ID, MY_RELAY_IDENTITY, RELAY_GRAPH},
    dht::{dht_get, dht_insert},
    haven::HavenLocator,
    n2r_socket::N2rClientSocket,
    network::{all_client_neighs, all_relay_neighs},
};
use crate::{
    control_protocol::{ChatError, ControlProtocol, DhtError, GlobalRpcArgs, GlobalRpcError},
    daemon::DaemonContext,
    global_rpc::transport::GlobalRpcTransport,
};

use super::chat::{ChatEntry, CHATS};

pub struct ControlProtocolImpl {
    ctx: DaemonContext,
}

impl ControlProtocolImpl {
    pub fn new(ctx: DaemonContext) -> Self {
        Self { ctx }
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
        let my_id = self
            .ctx
            .get(MY_RELAY_IDENTITY)
            .map(|id| get_node_label(&id.public().fingerprint()) + "\n[relay]")
            .unwrap_or(self.ctx.get(MY_CLIENT_ID).to_string() + "\n[client]");
        let my_shape = if self.ctx.init().in_routes.is_empty() {
            "rect"
        } else {
            "oval"
        };

        let all_relays =
            self.ctx
                .get(RELAY_GRAPH)
                .read()
                .all_nodes()
                .fold(String::new(), |acc, node| {
                    let node_label = get_node_label(&node);
                    if my_id.contains(&node_label) {
                        // if we're a relay, don't print two nodes for ourselves in the graphviz
                        acc
                    } else {
                        let _desc = self.ctx.get(RELAY_GRAPH).read().identity(&node).unwrap();
                        acc + &format!(
                            "{:?} [label={:?}, shape={}]\n",
                            node.to_string(),
                            node_label,
                            "oval, color=lightpink,style=filled".to_string()
                        )
                    }
                });

        let all_relay_adjs = self
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

        let all_my_adjs = all_relay_neighs(&self.ctx)
            .iter()
            .fold(String::new(), |acc, neigh| {
                acc + &format!("{:?} -- {:?};\n", my_id, neigh.to_string())
            });

        format!(
            "graph G {{
                    rankdir=\"LR\"
                    {:?} [shape={},color=lightblue,style=filled]
                {}
                {}
                {}
            }}",
            my_id, my_shape, all_relays, all_relay_adjs, all_my_adjs
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

    async fn list_neighbors(&self) -> Vec<Either<ClientId, RelayFingerprint>> {
        let relays = all_relay_neighs(&self.ctx);
        let clients = all_client_neighs(&self.ctx);
        let neighbors: Vec<Either<ClientId, RelayFingerprint>> = relays
            .into_iter()
            .map(|r| Either::Right(r))
            .chain(clients.into_iter().map(|c| Either::Left(c)))
            .collect();
        neighbors
    }

    /// returns not only all active chats but also all potential chat destinations
    async fn list_chats(&self) -> HashMap<String, (Option<ChatEntry>, u32)> {
        let mut chat_info: HashMap<String, (Option<ChatEntry>, u32)> = self
            .ctx
            .get(CHATS)
            .all_chats()
            .into_iter()
            .map(|(neigh, info)| (neigh.to_string(), info))
            .collect();
        let mut client_neighs: Vec<String> = all_client_neighs(&self.ctx)
            .into_iter()
            .map(|x| x.to_string())
            .collect();
        let mut relay_neighs = all_relay_neighs(&self.ctx)
            .into_iter()
            .map(|x| x.to_string())
            .collect();
        client_neighs.append(&mut relay_neighs);
        for neigh in client_neighs {
            if !chat_info.contains_key(&neigh) {
                chat_info.insert(neigh, (None, 0));
            }
        }
        chat_info
    }

    async fn get_chat(
        &self,
        src_prefix: String,
    ) -> Result<Vec<(bool, String, SystemTime)>, ChatError> {
        let neighbor =
            neigh_by_prefix(&self.ctx, &src_prefix).map_err(|e| ChatError::Get(format!("{e}")))?;
        let convo = self.ctx.get(CHATS).dump_convo(neighbor);
        Ok(convo
            .into_iter()
            .map(|entry| (entry.is_outgoing, entry.text, entry.time))
            .collect())
    }

    async fn send_chat(&self, dest_prefix: String, msg: String) -> Result<(), ChatError> {
        let neighbor = neigh_by_prefix(&self.ctx, &dest_prefix)
            .map_err(|e| ChatError::Send(format!("{e}")))?;
        let entry = ChatEntry::new_outgoing(msg);
        self.ctx.get(CHATS).record(neighbor, entry);
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

fn neigh_by_prefix(
    ctx: &DaemonContext,
    prefix: &str,
) -> anyhow::Result<Either<ClientId, RelayFingerprint>> {
    let valid_clients = all_client_neighs(ctx)
        .into_iter()
        .map(|client| Either::Left(client));
    let valid_relays = all_relay_neighs(ctx)
        .into_iter()
        .map(|relay| Either::Right(relay));
    let valid_neighs: Vec<Either<ClientId, RelayFingerprint>> = valid_clients
        .chain(valid_relays)
        .filter(|fp| fp.to_string().starts_with(prefix))
        .collect();

    if valid_neighs.len() == 1 {
        Ok(valid_neighs[0])
    } else if valid_neighs.is_empty() {
        anyhow::bail!("No neighbors with this prefix! Double check the spelling.")
    } else {
        anyhow::bail!("Prefix matches multiple neighbors! Try a longer prefix.")
    }
}
