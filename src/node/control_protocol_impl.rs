use std::collections::{BTreeMap, HashMap};

use async_trait::async_trait;
use earendil_crypt::{HavenFingerprint, RelayFingerprint};
use nanorpc::RpcTransport;
use serde_json::json;

use crate::{ChatEntry, v2h_node::HavenLocator};
use earendil_topology::NodeAddr;
use crate::control_protocol::RelayGraphInfo;

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
                .in_links
                .iter()
                .map(|(k, cfg)| {
                    (
                        k.clone(),
                        json!({
                            "connect": format!("<YOUR_IP>:{}", cfg.listen.port()),
                            "fingerprint": format!("{}", relay_config.identity.actualize_relay().expect("wrong relay identity format").public().fingerprint()),
                            "obfs": serde_json::to_value(&cfg.obfs).unwrap(),
                        }),
                    )
                })
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
        let my_fingerprint = match self.ctx.v2h.link_node().my_id() {
            earendil_lownet::NodeIdentity::Relay(id) => Some(id.public().fingerprint()),
            earendil_lownet::NodeIdentity::ClientBearer(_) => None,
        };

        let relay_graph = self.ctx.v2h.link_node().relay_graph();
        let relays: Vec<RelayFingerprint> = relay_graph.all_nodes().collect();

        let adjacencies: Vec<(RelayFingerprint, RelayFingerprint)> = relay_graph
            .all_adjacencies()
            .map(|adj| (adj.left, adj.right))
            .collect();
        let neighbors: Vec<NodeAddr> = self.ctx.v2h.link_node().all_neighs().clone();

        RelayGraphInfo {
            my_fingerprint,
            relays,
            adjacencies,
            neighbors,
        }
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
    async fn list_neighbors(&self) -> Vec<NodeAddr> {
        self.ctx.v2h.link_node().all_neighs()
    }

    async fn list_chats(&self) -> Result<HashMap<String, (Option<ChatEntry>, u32)>, ChatError> {
        todo!()
    }

    // true = outgoing, false = incoming
    async fn get_chat(&self, neighbor_prefix: String) -> Result<Vec<ChatEntry>, ChatError> {
        todo!()
    }

    async fn send_chat(&self, dest_neighbor_prefix: String, msg: String) -> Result<(), ChatError> {
        todo!()
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

}

fn get_node_label(fp: &RelayFingerprint) -> String {
    let node = fp.to_string();
    format!("{}..{}", &node[..4], &node[node.len() - 4..node.len()])
}

fn neigh_by_prefix(all_neighs: Vec<NodeAddr>, prefix: &str) -> anyhow::Result<NodeAddr> {
    let valid_neighs: Vec<NodeAddr> = all_neighs
        .into_iter()
        .filter(|id| id.to_string().starts_with(prefix))
        .collect();

    if valid_neighs.len() == 1 {
        Ok(valid_neighs[0])
    } else if valid_neighs.is_empty() {
        anyhow::bail!("No neighbors with this prefix! Double check the spelling.")
    } else {
        anyhow::bail!("Prefix matches multiple neighbors! Try a longer prefix.")
    }
}
