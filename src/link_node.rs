mod link_store;
mod payment_system;

mod route_util;

use bytes::Bytes;

mod types;

use std::{sync::Arc, u8};

use anyhow::Context;
use earendil_lownet::{Datagram, LowNet, NodeIdentity};
pub use link_store::*;

use earendil_crypt::{AnonEndpoint, RelayFingerprint, RemoteId};
use earendil_packet::{
    InnerPacket,
    Message,
    PeeledPacket,
    PrivacyConfig,
    RawPacket,
    ReplyDegarbler,
    Surb,
    RAW_PACKET_SIZE,
};
use earendil_topology::RelayGraph;

pub use payment_system::{Dummy, OnChain, PaymentSystem, PoW};
use route_util::{forward_route_to, route_to_instructs};
pub use types::{IncomingMsg, LinkConfig, NeighborId, NeighborIdSecret};

/// An implementation of the link-level interface.
pub struct LinkNode {
    lownet: Arc<LowNet>,
    privacy: PrivacyConfig,
}

impl LinkNode {
    /// Creates a new link node.
    pub fn new(cfg: LinkConfig) -> anyhow::Result<Self> {
        use earendil_lownet::{InLinkConfig, OutLinkConfig, LowNetConfig};

        let identity = if let Some((relay_id, _)) = &cfg.relay_config {
            NodeIdentity::Relay(*relay_id)
        } else {
            NodeIdentity::ClientBearer(rand::random())
        };

        let in_links = cfg
            .relay_config
            .as_ref()
            .map(|(_, routes)| {
                routes
                    .values()
                    .map(|r| InLinkConfig {
                        listen: r.listen,
                        obfs: match r.obfs.clone() {
                            crate::config::ObfsConfig::None => earendil_lownet::ObfsConfig::None,
                            crate::config::ObfsConfig::Sosistab3(s) => earendil_lownet::ObfsConfig::Sosistab3(s),
                        },
                    })
                    .collect()
            })
            .unwrap_or_default();

        let out_links = cfg
            .out_routes
            .values()
            .map(|r| OutLinkConfig {
                connect: r.connect.clone(),
                fingerprint: r.fingerprint,
                obfs: match r.obfs.clone() {
                    crate::config::ObfsConfig::None => earendil_lownet::ObfsConfig::None,
                    crate::config::ObfsConfig::Sosistab3(s) => earendil_lownet::ObfsConfig::Sosistab3(s),
                },
            })
            .collect();

        let lownet = LowNet::new(LowNetConfig {
            in_links,
            out_links,
            identity,
        });

        Ok(Self {
            lownet: Arc::new(lownet),
            privacy: cfg.privacy_config,
        })
    }

    /// Sends a "forward" packet, which could be either a message or a batch of reply blocks.
    pub async fn send_forward(
        &self,
        packet: InnerPacket,
        src: AnonEndpoint,
        dest_relay: RelayFingerprint,
    ) -> anyhow::Result<()> {
        let tele: earendil_lownet::Topology = self.lownet.topology();
        let datagram = {
            let graph = tele.graph().read().unwrap();
            let route = forward_route_to(&graph, dest_relay, self.privacy.max_peelers)?;
            let instructs = route_to_instructs(&graph, &route)?;
            let dest_dh = graph
                .identity(dest_relay)
                .context(format!(
                    "couldn't get the identity of the destination fp {dest_relay}"
                ))?
                .onion_pk;

            let raw_packet = RawPacket::new_normal(
                &instructs,
                &dest_dh,
                packet,
                RemoteId::Anon(src),
                self.privacy,
            )?;
            Datagram {
                ttl: u8::MAX,
                dest_addr: instructs.get(0).context("no first peeler")?.next_hop,
                payload: bytemuck::bytes_of(&raw_packet).to_vec().into(),
            }
        };

        self.lownet.send(datagram).await;
        Ok(())
    }

    /// Sends a "backwards" packet, which consumes a reply block.
    pub async fn send_backwards(&self, reply_block: Surb, message: Message) -> anyhow::Result<()> {
        if let NodeIdentity::Relay(relay) = self.lownet.topology().identity() {
            let raw_packet = RawPacket::new_reply(
                &reply_block,
                InnerPacket::Message(message.clone()),
                &RemoteId::Relay(relay.public().fingerprint()),
            )?;
            let datagram = Datagram {
                ttl: u8::MAX,
                dest_addr: reply_block.first_peeler,
                payload: bytemuck::bytes_of(&raw_packet).to_vec().into(),
            };
            self.lownet.send(datagram).await;
            Ok(())
        } else {
            anyhow::bail!("our identity must be relay to send backwards packets")
        }
    }

    /// Constructs a reply block back from the given relay.
    pub fn new_surb(
        &self,
        my_anon_id: AnonEndpoint,
    ) -> anyhow::Result<(Surb, u64, ReplyDegarbler)> {
        let topo = self.lownet.topology();
        let graph = topo.graph().read().unwrap();
        let my_fp = match topo.identity() {
            NodeIdentity::Relay(relay) => relay.public().fingerprint(),
            NodeIdentity::ClientBearer(_) => anyhow::bail!("cannot build surb as client"),
        };
        let route = forward_route_to(&graph, my_fp, self.privacy.max_peelers)?;
        let instructs = route_to_instructs(&graph, &route)?;
        let opk = topo
            .relay_identity_descriptor()
            .context("no relay identity")?
            .onion_pk;

        let (surb, (id, deg)) = Surb::new(
            &instructs,
            instructs.get(0).context("no first peeler")?.next_hop,
            &opk,
            my_anon_id,
            self.privacy,
        )?;
        Ok((surb, id, deg))
    }


    /// Receives an incoming message. Blocks until we have something that's for us, and not to be forwarded elsewhere.
    pub async fn recv(&self) -> IncomingMsg {
        use std::time::Duration;

        loop {
            let dg = self.lownet.recv().await;

            if dg.payload.len() != RAW_PACKET_SIZE {
                tracing::warn!(size = dg.payload.len(), "invalid packet size");
                continue;
            }

            let raw_pkt: &RawPacket = match bytemuck::try_from_bytes(&dg.payload) {
                Ok(pkt) => pkt,
                Err(_) => {
                    tracing::warn!("could not cast bytes to RawPacket");
                    continue;
                }
            };

            let peeled = match raw_pkt.peel(self.lownet.topology().dh_secret()) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(err = debug(&e), "failed to peel packet");
                    continue;
                }
            };

            match peeled {
                PeeledPacket::Relay { next_peeler, pkt, delay_ms } => {
                    let lownet = self.lownet.clone();
                    let ttl = dg.ttl;
                    smolscale::spawn(async move {
                        smol::Timer::after(Duration::from_millis(delay_ms as u64)).await;
                        let dg = Datagram {
                            ttl,
                            dest_addr: next_peeler,
                            payload: bytemuck::bytes_of(&pkt).to_vec().into(),
                        };
                        lownet.send(dg).await;
                    })
                    .detach();
                }
                PeeledPacket::Received { from, pkt } => {
                    return IncomingMsg::Forward { from, body: pkt };
                }
                PeeledPacket::GarbledReply { surb_id, pkt } => {
                    return IncomingMsg::Backward {
                        rb_id: surb_id,
                        body: Bytes::copy_from_slice(&pkt[..]),
                    };
                }
            }
        }
    }

    /// Gets all the currently known relays.
    pub fn all_relays(&self) -> Vec<RelayFingerprint> {
        let topo = self.lownet.topology();
        topo.graph().read().unwrap().all_nodes().collect()
    }

    /// Gets the current relay graph.
    pub fn relay_graph(&self) -> RelayGraph {
        self.lownet.topology().graph().read().unwrap().clone()
    }

    /// Gets my identity.
    pub fn my_id(&self) -> NeighborIdSecret {
        match self.lownet.topology().identity() {
            NodeIdentity::Relay(id) => NeighborIdSecret::Relay(id),
            NodeIdentity::ClientBearer(id) => NeighborIdSecret::Client(id as u64),
        }
    }

    /// Gets all our currently connected neighbors.
    pub fn all_neighs(&self) -> Vec<NeighborId> {
        Vec::new()
    }

    pub async fn timeseries_stats(&self, key: String, start: i64, end: i64) -> Vec<(i64, f64)> {
        let _ = (key, start, end);
        Vec::new()
    }

    pub fn privacy_config(&self) -> PrivacyConfig {
        self.privacy
    }
}
