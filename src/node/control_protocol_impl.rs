use std::collections::{BTreeMap, HashMap};

use async_trait::async_trait;
use earendil_crypt::{HavenFingerprint, RelayFingerprint};
use nanorpc::RpcTransport;
use serde_json::json;

use crate::{
    config::{InRouteConfig, PriceConfig},
    control_protocol::{DebtError, RelayGraphInfo},
    v2h_node::HavenLocator,
    ChatEntry, NeighborId,
};

use super::NodeCtx;
use crate::control_protocol::{
    ChatError, ConfigError, ControlProtocol, DhtError, GlobalRpcArgs, GlobalRpcError,
};
pub struct ControlProtocolImpl {
    ctx: NodeCtx,
}

impl ControlProtocolImpl {
    pub fn new(ctx: NodeCtx) -> Self {
        Self { ctx }
    }
}

#[async_trait]
impl ControlProtocol for ControlProtocolImpl {
    async fn havens_info(&self) -> Result<Vec<(String, String)>, ConfigError> {
        self.ctx
            .config
            .havens
            .iter()
            .map(|haven_cfg| match haven_cfg.identity.actualize_haven() {
                Ok(secret) => {
                    let fp = secret.public().fingerprint();
                    match haven_cfg.handler {
                        crate::config::HavenHandler::TcpService { upstream: _ } => Ok((
                            "TcpService".to_string(),
                            fp.to_string() + ":" + &haven_cfg.listen_port.to_string(),
                        )),
                        _ => Err(ConfigError::Error(
                            "Only TcpService handler is supported".to_string(),
                        )),
                    }
                }
                Err(err) => Err(ConfigError::Error(err.to_string())),
            })
            .collect()
    }

    async fn my_routes(&self) -> serde_json::Value {
        if let Some(relay_config) = self.ctx.config.relay_config.clone() {
            let lala: BTreeMap<String, serde_json::Value> = relay_config
                .in_routes
                .iter()
                .map(
                    |(
                        k,
                        InRouteConfig {
                            listen,
                            obfs,
                            price_config,
                        },
                    )| {
                        let client_price_config = PriceConfig { inbound_price: price_config.outbound_max_price, inbound_debt_limit: price_config.outbound_min_debt_limit, outbound_max_price: price_config.inbound_price, outbound_min_debt_limit: price_config.inbound_debt_limit };
                        (
                            k.clone(),
                            json!({
                                "connect": format!("<YOUR_IP>:{}", listen.port()),
                                "fingerprint": format!("{}", relay_config.identity.actualize_relay().expect("wrong relay identity format").public().fingerprint()),
                                "obfs": serde_json::to_value(obfs).unwrap(),
                                "price_config": serde_json::to_value(client_price_config).unwrap(),
                            }),
                        )
                    },
                )
                .collect();
            serde_json::to_value(lala).unwrap()
        } else {
            "This is a client node. Client nodes do not have in-routes.".into()
        }
    }

    async fn relay_graphviz(&self) -> String {
        todo!()
    }

    async fn relay_graph_info(&self) -> RelayGraphInfo {
        todo!()
        // let my_fingerprint = match self.ctx.;

        // let relay_graph = self.ctx.v2h.link_node().relay_graph();
        // let relays: Vec<RelayFingerprint> = relay_graph.all_nodes().collect();

        // let adjacencies: Vec<(RelayFingerprint, RelayFingerprint)> = relay_graph
        //     .all_adjacencies()
        //     .map(|adj| (adj.left, adj.right))
        //     .collect();
        // let neighbors: Vec<NeighborId> = self.ctx.v2h.link_node().all_neighs().clone();

        // RelayGraphInfo {
        //     my_fingerprint,
        //     relays,
        //     adjacencies,
        //     neighbors,
        // }
    }

    // ------------- functionality to test GlobalRpc --------------
    async fn send_global_rpc(
        &self,
        args: GlobalRpcArgs,
    ) -> Result<serde_json::Value, GlobalRpcError> {
        let grpc_transport = self.ctx.v2h.grpc_transport(args.destination);
        let res = if let Some(res) = grpc_transport
            .call(&args.method, &args.args)
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

    async fn insert_rendezvous(&self, locator: HavenLocator) {
        self.ctx.v2h.dht_insert(locator).await
    }

    async fn get_rendezvous(
        &self,
        fingerprint: HavenFingerprint,
    ) -> Result<Option<HavenLocator>, DhtError> {
        self.ctx.v2h.dht_get(fingerprint).await.map_err(|e| {
            tracing::debug!("dht_get failed with : {e}");
            DhtError::DhtGetFailed(e.to_string())
        })
    }

    // ---------------- chat-related functionality -----------------
    async fn list_neighbors(&self) -> Vec<NeighborId> {
        let graph = self.ctx.v2h.link_node().netgraph();
        graph
            .connected_clients()
            .into_iter()
            .map(NeighborId::Client)
            .chain(graph.connected_relays().into_iter().map(NeighborId::Relay))
            .collect()
    }

    async fn list_chats(&self) -> Result<HashMap<String, (Option<ChatEntry>, u32)>, ChatError> {
        let chats_summary = self
            .ctx
            .v2h
            .link_node()
            .get_chat_summary()
            .await
            .map_err(|e| ChatError::Db(e.to_string()))?;

        let mut res = HashMap::new();
        for (neigh, last, count) in chats_summary {
            res.insert(neigh.to_string(), (Some(last), count));
        }
        // add all neighbors that are not in the chat summary
        for neigh in self.list_neighbors().await {
            res.entry(neigh.to_string()).or_insert((None, 0));
        }
        Ok(res)
    }

    // true = outgoing, false = incoming
    async fn get_chat(&self, neighbor_prefix: String) -> Result<Vec<ChatEntry>, ChatError> {
        let neighbor = neigh_by_prefix(self.list_neighbors().await, &neighbor_prefix)
            .map_err(|e| ChatError::Get(e.to_string()))?;
        self.ctx
            .v2h
            .link_node()
            .get_chat_history(neighbor)
            .await
            .map_err(|e| ChatError::Get(e.to_string()))
    }

    async fn send_chat(&self, dest_neighbor_prefix: String, msg: String) -> Result<(), ChatError> {
        let neighbor = neigh_by_prefix(self.list_neighbors().await, &dest_neighbor_prefix)
            .map_err(|e| ChatError::Send(e.to_string()))?;
        self.ctx
            .v2h
            .link_node()
            .send_chat(neighbor, msg)
            .await
            .map_err(|e| ChatError::Send(e.to_string()))
    }

    async fn timeseries_stats(&self, key: String, start: i64, end: i64) -> Vec<(i64, f64)> {
        let timeseries = self
            .ctx
            .v2h
            .link_node()
            .timeseries_stats(key.clone(), start, end)
            .await;
        tracing::debug!("num stats for {key}: {}", timeseries.len());

        timeseries
    }

    async fn get_debt_summary(&self) -> Result<HashMap<String, f64>, DebtError> {
        self.ctx
            .v2h
            .link_node()
            .get_debt_summary()
            .await
            .map_err(|e| {
                tracing::debug!("get_debt_summary failed with : {e}");
                DebtError::Get(e.to_string())
            })
    }

    async fn get_debt(&self, neighbor_prefix: String) -> Result<f64, DebtError> {
        let neighbor = neigh_by_prefix(self.list_neighbors().await, &neighbor_prefix)
            .map_err(|e| DebtError::Get(e.to_string()))?;
        self.ctx
            .v2h
            .link_node()
            .get_debt(neighbor)
            .await
            .map_err(|e| DebtError::Get(e.to_string()))
    }
}

fn get_node_label(fp: &RelayFingerprint) -> String {
    let node = fp.to_string();
    format!("{}..{}", &node[..4], &node[node.len() - 4..node.len()])
}

fn neigh_by_prefix(all_neighs: Vec<NeighborId>, prefix: &str) -> anyhow::Result<NeighborId> {
    let valid_neighs: Vec<NeighborId> = all_neighs
        .into_iter()
        .filter(|id| match id {
            NeighborId::Client(id) => id.to_string().starts_with(prefix),
            NeighborId::Relay(id) => id.to_string().starts_with(prefix),
        })
        .collect();

    if valid_neighs.len() == 1 {
        Ok(valid_neighs[0])
    } else if valid_neighs.is_empty() {
        anyhow::bail!("No neighbors with this prefix! Double check the spelling.")
    } else {
        anyhow::bail!("Prefix matches multiple neighbors! Try a longer prefix.")
    }
}
