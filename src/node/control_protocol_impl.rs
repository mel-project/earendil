use std::collections::BTreeMap;

use async_trait::async_trait;
use earendil_crypt::{HavenFingerprint, RelayFingerprint};
use itertools::Itertools;
use nanorpc::RpcTransport;
use serde_json::json;

use crate::control_protocol::RelayGraphInfo;
use crate::haven_layer::HavenLocator;
use earendil_topology::NodeAddr;

use super::NodeCtx;
use crate::control_protocol::{
    ConfigError, ControlProtocol, DhtError, GlobalRpcArgs, GlobalRpcError,
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
        use std::cmp::Ord;

        let (my_id, my_shape) = match self.ctx.haven.transport_layer().my_id() {
            earendil_lownet::NodeIdentity::ClientBearer(id) => {
                (format!("{}\n[client]", id), "rect")
            }
            earendil_lownet::NodeIdentity::Relay(id) => (
                format!("{}\n[relay]", get_node_label(&id.public().fingerprint())),
                "oval",
            ),
        };

        let relay_graph = self.ctx.haven.transport_layer().relay_graph();

        let all_relays = relay_graph.all_nodes().fold(String::new(), |acc, node| {
            let node_label = get_node_label(&node);
            if my_id.contains(&node_label) {
                acc
            } else {
                acc + &format!(
                    "    {:?} [label={:?}, shape={}]\n",
                    node.to_string(),
                    node_label,
                    "oval, color=lightpink,style=filled"
                )
            }
        });

        let all_relay_adjs = relay_graph
            .all_adjacencies()
            .sorted_by(|a, b| Ord::cmp(&a.left, &b.left))
            .fold(String::new(), |acc, adj| {
                acc + &format!(
                    "    {:?} -- {:?};\n",
                    adj.left.to_string(),
                    adj.right.to_string()
                )
            });

        let all_my_adjs = self
            .ctx
            .haven
            .transport_layer()
            .all_neighs()
            .iter()
            .filter(|neigh| neigh.client_id == 0)
            .fold(String::new(), |acc, neigh| {
                acc + &format!("    {:?} -- {:?};\n", my_id, neigh.relay.to_string())
            });

        format!(
            "graph G {{\n    rankdir=\"LR\"\n    # my ID\n    {:?} [shape={},color=lightblue,style=filled]\n\n    # all relays\n{}\n    # all relay connections\n{}\n    # all my connections\n{}\n}}",
            my_id, my_shape, all_relays, all_relay_adjs, all_my_adjs
        )
    }

    async fn relay_graph_info(&self) -> RelayGraphInfo {
        let my_fingerprint = match self.ctx.haven.transport_layer().my_id() {
            earendil_lownet::NodeIdentity::Relay(id) => Some(id.public().fingerprint()),
            earendil_lownet::NodeIdentity::ClientBearer(_) => None,
        };

        let relay_graph = self.ctx.haven.transport_layer().relay_graph();
        let relays: Vec<RelayFingerprint> = relay_graph.all_nodes().collect();

        let adjacencies: Vec<(RelayFingerprint, RelayFingerprint)> = relay_graph
            .all_adjacencies()
            .map(|adj| (adj.left, adj.right))
            .collect();
        let neighbors: Vec<NodeAddr> = self.ctx.haven.transport_layer().all_neighs().clone();

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
        let grpc_transport = self.ctx.haven.grpc_transport(args.destination);
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
        self.ctx.haven.dht_insert(locator).await
    }

    async fn get_rendezvous(
        &self,
        fingerprint: HavenFingerprint,
    ) -> Result<Option<HavenLocator>, DhtError> {
        self.ctx.haven.dht_get(fingerprint).await.map_err(|e| {
            tracing::debug!("dht_get failed with : {e}");
            DhtError::DhtGetFailed(e.to_string())
        })
    }

    async fn timeseries_stats(&self, key: String, start: i64, end: i64) -> Vec<(i64, f64)> {
        vec![]
    }
}

fn get_node_label(fp: &RelayFingerprint) -> String {
    let node = fp.to_string();
    format!("{}..{}", &node[..4], &node[node.len() - 4..])
}
