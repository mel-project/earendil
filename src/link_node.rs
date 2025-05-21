mod link;

mod link_store;
mod pascal;
mod payment_system;

mod route_util;

pub mod stats;

mod types;

use std::{sync::Arc, u8};

use anyhow::Context;
use earendil_lownet::{Datagram, LowNet, NodeIdentity};
pub use link_store::*;

use earendil_crypt::{AnonEndpoint, RelayFingerprint, RemoteId};
use earendil_packet::{InnerPacket, Message, PrivacyConfig, RawPacket, ReplyDegarbler, Surb};
use earendil_topology::{NodeAddr, RelayGraph};

pub use payment_system::{Dummy, OnChain, PaymentSystem, PoW};
use route_util::{forward_route_to, route_to_instructs};
pub use types::{IncomingMsg, LinkConfig, NeighborId, NeighborIdSecret};

/// An implementation of the link-level interface.
pub struct LinkNode {
    lownet: Arc<LowNet>,
}

impl LinkNode {
    /// Creates a new link node.
    pub fn new(cfg: LinkConfig) -> anyhow::Result<Self> {
        todo!()
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
            let route = forward_route_to(&graph, dest_relay, self.privacy_config().max_peelers)?;
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
                self.privacy_config(),
            )?;
            Datagram {
                ttl: u8::MAX,
                dest_addr: NodeAddr::new(instructs.get(0).context("no first peeler")?.next_hop, 0),
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
                dest_addr: NodeAddr::new(reply_block.first_peeler, 0),
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
        todo!()
    }

    /// Sends a raw packet.
    async fn send_raw(&self, raw: RawPacket, next_peeler: RelayFingerprint) {
        todo!()
    }

    /// Receives an incoming message. Blocks until we have something that's for us, and not to be forwarded elsewhere.
    pub async fn recv(&self) -> IncomingMsg {
        todo!()
    }

    /// Gets all the currently known relays.
    pub fn all_relays(&self) -> Vec<RelayFingerprint> {
        todo!()
    }

    /// Gets the current relay graph.
    pub fn relay_graph(&self) -> RelayGraph {
        todo!()
    }

    /// Gets my identity.
    pub fn my_id(&self) -> NeighborIdSecret {
        todo!()
    }

    /// Gets all our currently connected neighbors.
    pub fn all_neighs(&self) -> Vec<NeighborId> {
        todo!()
    }

    pub async fn timeseries_stats(&self, key: String, start: i64, end: i64) -> Vec<(i64, f64)> {
        todo!()
    }

    pub fn privacy_config(&self) -> PrivacyConfig {
        todo!()
    }
}
