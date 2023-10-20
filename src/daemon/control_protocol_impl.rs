use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use earendil_crypt::Fingerprint;
use earendil_packet::{ForwardInstruction, InnerPacket, RawPacket, ReplyBlock};
use earendil_topology::RelayGraph;
use parking_lot::RwLock;
use sosistab2::ObfsUdpSecret;

use crate::{
    config::{InRouteConfig, OutRouteConfig},
    control_protocol::{ControlProtocol, SendMessageArgs, SendMessageError},
    daemon::DaemonContext,
};

pub struct ControlProtocolImpl {
    pub ctx: DaemonContext,
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
        let (public_isk, anon_source) = if let Some(id) = args.id {
            // get anonymous identity
            let x = self.ctx.anon_identities.write().get(&id);
            log::debug!(
                "using anon identity with fingerprint {:?}",
                x.public().fingerprint()
            );
            (Arc::new(x), true)
        } else {
            (self.ctx.identity.clone(), false)
        };

        let maybe_reply_block = self.ctx.anon_destinations.write().get(&args.destination);
        if let Some(reply_block) = maybe_reply_block {
            if anon_source {
                return Err(SendMessageError::NoAnonId);
            }
            log::debug!("sending message with reply block");
            let inner = InnerPacket::Message(Bytes::copy_from_slice(&args.content));
            let raw_packet = RawPacket::from_reply_block(&reply_block, inner, &public_isk)?;
            self.ctx.table.inject_asif_incoming(raw_packet).await;
        } else {
            let route = self
                .ctx
                .relay_graph
                .read()
                .find_shortest_path(&self.ctx.identity.public().fingerprint(), &args.destination)
                .ok_or(SendMessageError::NoRoute)?;
            let instructs = route_to_instructs(route, self.ctx.relay_graph.clone())?;
            log::debug!("instructs = {:?}", instructs);
            let their_opk = self
                .ctx
                .relay_graph
                .read()
                .identity(&args.destination)
                .ok_or(SendMessageError::NoOnionPublic(args.destination))?
                .onion_pk;
            let (wrapped_onion, _) = RawPacket::new(
                &instructs,
                &their_opk,
                InnerPacket::Message(args.content),
                &[0; 20],
                &public_isk,
            )?;
            // we send the onion by treating it as a message addressed to ourselves
            self.ctx.table.inject_asif_incoming(wrapped_onion).await;

            // if we want to use an anon source, send a batch of reply blocks
            if anon_source {
                // currently the path for every one of them is the same; will want to change this in the future
                let n = 8;
                let reverse_route = self
                    .ctx
                    .relay_graph
                    .read()
                    .find_shortest_path(
                        &args.destination,
                        &self.ctx.identity.public().fingerprint(),
                    )
                    .ok_or(SendMessageError::NoRoute)?;
                let reverse_instructs =
                    route_to_instructs(reverse_route, self.ctx.relay_graph.clone())?;
                log::debug!("reverse_instructs = {:?}", reverse_instructs);

                let mut rbs: Vec<ReplyBlock> = vec![];
                for _ in 0..n {
                    let (rb, (id, degarbler)) =
                        ReplyBlock::new(&reverse_instructs, &self.ctx.onion_sk.public())
                            .map_err(|_| SendMessageError::ReplyBlockFailed)?;
                    rbs.push(rb);
                    self.ctx.degarblers.insert(id, degarbler);
                }
                let (wrapped_rb_onion, _) = RawPacket::new(
                    &instructs,
                    &their_opk,
                    InnerPacket::ReplyBlocks(rbs),
                    &[0; 20],
                    &public_isk,
                )?;
                // we send the onion by treating it as a message addressed to ourselves
                self.ctx.table.inject_asif_incoming(wrapped_rb_onion).await;
            }
        }
        Ok(())
    }

    async fn recv_message(&self) -> Option<(Bytes, Fingerprint)> {
        self.ctx.incoming.pop().ok()
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
}

fn route_to_instructs(
    route: Vec<Fingerprint>,
    relay_graph: Arc<RwLock<RelayGraph>>,
) -> Result<Vec<ForwardInstruction>, SendMessageError> {
    route
        .windows(2)
        .map(|wind| {
            let this = wind[0];
            let next = wind[1];
            let this_pubkey = relay_graph
                .read()
                .identity(&this)
                .ok_or(SendMessageError::NoOnionPublic(this))?
                .onion_pk;
            Ok(ForwardInstruction {
                this_pubkey,
                next_fingerprint: next,
            })
        })
        .collect()
}
