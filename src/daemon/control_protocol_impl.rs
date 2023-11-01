use std::collections::BTreeMap;

use async_trait::async_trait;
use earendil_crypt::Fingerprint;
use earendil_packet::Message;
use nanorpc::RpcTransport;
use sosistab2::ObfsUdpSecret;

use crate::{
    config::{InRouteConfig, OutRouteConfig},
    control_protocol::{
        ControlProtocol, GlobalRpcArgs, GlobalRpcError, SendMessageArgs, SendMessageError,
    },
    daemon::DaemonContext,
};

use super::global_rpc::transport::GlobalRpcTransport;

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

    async fn send_message(&self, args: SendMessageArgs) -> Result<(), SendMessageError> {
        self.ctx.send_message(args).await
    }

    async fn recv_message(&self) -> Option<(Message, Fingerprint)> {
        self.ctx.unhandled_incoming.pop().ok()
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

    async fn send_global_rpc(
        &self,
        send_args: GlobalRpcArgs,
    ) -> Result<serde_json::Value, GlobalRpcError> {
        let client = GlobalRpcTransport::new(self.ctx.clone(), send_args.destination);
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
}
