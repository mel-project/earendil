mod link;

mod link_store;
mod pascal;
mod payment_system;

mod route_util;

pub mod stats;

mod types;

pub use link_store::*;

use earendil_crypt::{AnonEndpoint, RelayFingerprint};
use earendil_packet::{InnerPacket, Message, PrivacyConfig, RawPacket, ReplyDegarbler, Surb};
use earendil_topology::RelayGraph;

pub use payment_system::{Dummy, OnChain, PaymentSystem, PoW};
pub use types::{IncomingMsg, LinkConfig, NeighborId, NeighborIdSecret};

/// An implementation of the link-level interface.
pub struct LinkNode {}

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
        todo!()
    }

    /// Sends a "backwards" packet, which consumes a reply block.
    pub async fn send_backwards(&self, reply_block: Surb, message: Message) -> anyhow::Result<()> {
        todo!()
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
