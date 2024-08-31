mod client_proc;
mod link_protocol;
mod link_store;
mod payment_system;
mod relay_proc;
mod route_util;
pub mod stats;
mod switch_proc;
mod types;

use std::{collections::HashMap, sync::Arc};

use anyhow::Context as _;
use client_proc::ClientProcess;
use earendil_crypt::{AnonEndpoint, RelayFingerprint};
use earendil_packet::{
    InnerPacket, Message, PrivacyConfig, RawPacket, RawPacketWithNext, ReplyDegarbler, Surb,
};
use earendil_topology::RelayGraph;
use haiyuu::{Handle, Process};
pub use link_store::*;

use parking_lot::RwLock;
pub use payment_system::{Dummy, OnChain, PaymentSystem, PoW};

use relay_proc::{RelayMsg, RelayProcess};
use route_util::{forward_route_to, route_to_instructs};
use smol::channel::Receiver;
pub use types::{IncomingMsg, LinkConfig, NeighborId, NeighborIdSecret};
/// An implementation of the link-level interface.
pub struct LinkNode {
    cfg: LinkConfig,
    process: either::Either<Handle<RelayProcess>, Handle<ClientProcess>>,
    graph: Arc<RwLock<RelayGraph>>,

    recv_incoming: Receiver<IncomingMsg>,
}

impl LinkNode {
    /// Creates a new link node.
    pub fn new(cfg: LinkConfig) -> anyhow::Result<Self> {
        let (send_incoming, recv_incoming) = smol::channel::unbounded();
        let graph = Arc::new(RwLock::new(RelayGraph::new()));
        let process = if let Some((identity, in_routes)) = &cfg.relay_config {
            either::Either::Left(
                RelayProcess::new(
                    *identity,
                    in_routes.clone(),
                    cfg.out_routes.clone(),
                    graph.clone(),
                    send_incoming,
                )
                .spawn_smolscale(),
            )
        } else {
            todo!()
        };

        Ok(Self {
            cfg,
            process,
            graph,
            recv_incoming,
        })
    }

    /// Sends a "forward" packet, which could be either a message or a batch of reply blocks.
    pub async fn send_forward(
        &self,
        packet: InnerPacket,
        src: AnonEndpoint,
        dest_relay: RelayFingerprint,
    ) -> anyhow::Result<()> {
        let raw_packet = self.package_raw(packet, src, dest_relay)?;
        match self.process.as_ref() {
            either::Either::Left(proc) => {
                proc.send(RelayMsg::PeelForward(raw_packet)).await?;
            }
            either::Either::Right(_) => todo!(),
        }
        anyhow::Ok(())
    }

    fn package_raw(
        &self,
        packet: InnerPacket,
        src: AnonEndpoint,
        dest_relay: RelayFingerprint,
    ) -> anyhow::Result<RawPacketWithNext> {
        let privacy_config = self.privacy_config();
        let graph = self.graph.read();
        let route = forward_route_to(&graph, dest_relay, privacy_config.max_peelers)?;
        let first_peeler = *route.first().context("empty route")?;
        let instructs = route_to_instructs(&graph, &route).context("route_to_instructs failed")?;
        let dest_opk = graph
            .identity(&dest_relay)
            .context(format!(
                "couldn't get the identity of the destination fp {dest_relay}"
            ))?
            .onion_pk;
        Ok(RawPacketWithNext {
            packet: RawPacket::new_normal(
                &instructs,
                &dest_opk,
                packet,
                earendil_crypt::RemoteId::Anon(src),
                privacy_config,
            )?,
            next_peeler: first_peeler,
        })
    }

    /// Sends a "backwards" packet, which consumes a SURB.
    pub async fn send_backwards(&self, surb: Surb, message: Message) -> anyhow::Result<()> {
        if let either::Either::Left(relay) = &self.process {
            relay.send(RelayMsg::Backwards(surb, message)).await?;
            Ok(())
        } else {
            anyhow::bail!("must be a relay to send backwards packets")
        }
    }

    /// Constructs a reply block back from the given relay.
    pub fn new_surb(
        &self,
        my_anon_id: AnonEndpoint,
    ) -> anyhow::Result<(Surb, u64, ReplyDegarbler)> {
        let destination = self.surb_destination();
        let graph = self.graph.read();
        let dest_opk = graph
            .identity(&destination)
            .context(format!(
                "destination {destination} is surprisingly not in our RelayGraph"
            ))?
            .onion_pk;

        let privacy_cfg = self.privacy_config();

        let reverse_route = forward_route_to(&graph, destination, privacy_cfg.max_peelers)?;
        let reverse_instructs = route_to_instructs(&graph, &reverse_route)?;
        let my_client_id = match self.ctx.my_id {
            NeighborIdSecret::Relay(_) => 0, // special ClientId for relays
            NeighborIdSecret::Client(id) => id,
        };

        let (surb, (id, degarbler)) = Surb::new(
            &reverse_instructs,
            reverse_route[0],
            &dest_opk,
            my_client_id,
            my_anon_id,
            privacy_cfg,
        )
        .context("cannot build reply block")?;
        Ok((surb, id, degarbler))
    }

    fn surb_destination(&self) -> RelayFingerprint {
        match &self.cfg.relay_config {
            Some(val) => val.0.public().fingerprint(),
            None => todo!(),
        }
    }

    /// Sends a raw packet.
    async fn send_raw(&self, raw: RawPacket, next_peeler: RelayFingerprint) {
        todo!()
    }

    /// Receives an incoming message. Blocks until we have something that's for us, and not to be forwarded elsewhere.
    pub async fn recv(&self) -> IncomingMsg {
        self.recv_incoming.recv().await.unwrap()
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

    /// Sends a chat message to a neighbor.
    pub async fn send_chat(&self, neighbor: NeighborId, text: String) -> anyhow::Result<()> {
        todo!()
    }

    /// Gets the entire chat history with a neighbor.
    pub async fn get_chat_history(&self, neighbor: NeighborId) -> anyhow::Result<Vec<ChatEntry>> {
        todo!()
    }

    pub async fn get_chat_summary(&self) -> anyhow::Result<Vec<(NeighborId, ChatEntry, u32)>> {
        todo!()
    }

    pub async fn get_debt_summary(&self) -> anyhow::Result<HashMap<String, f64>> {
        todo!()
    }

    pub async fn get_debt(&self, neighbor: NeighborId) -> anyhow::Result<f64> {
        todo!()
    }

    pub async fn timeseries_stats(&self, key: String, start: i64, end: i64) -> Vec<(i64, f64)> {
        todo!()
    }

    pub fn privacy_config(&self) -> PrivacyConfig {
        todo!()
    }
}
