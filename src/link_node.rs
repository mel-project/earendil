mod client_proc;
mod gossip;
mod link_protocol;
mod link_store;
mod netgraph;
mod payment_system;
mod relay_proc;

pub mod stats;
mod switch_proc;
mod types;

use std::collections::HashMap;

use anyhow::Context as _;
use client_proc::{ClientMsg, ClientProcess};
use earendil_crypt::{AnonEndpoint, ClientId, RelayFingerprint};
use earendil_packet::{InnerPacket, Message, RawPacket, RawPacketWithNext, ReplyDegarbler, Surb};
use earendil_topology::RelayGraph;
use haiyuu::{Handle, Process};
pub use link_store::*;

use netgraph::NetGraph;

pub use payment_system::{Dummy, OnChain, PaymentSystem, PoW};

use rand::seq::SliceRandom;
use relay_proc::{RelayMsg, RelayProcess};

use smol::channel::Receiver;
pub use types::{IncomingMsg, LinkConfig, NeighborId};

/// An implementation of the link-level interface.
pub struct LinkNode {
    cfg: LinkConfig,
    process: either::Either<Handle<RelayProcess>, Handle<ClientProcess>>,
    client_id: ClientId,
    graph: NetGraph,

    recv_incoming: Receiver<IncomingMsg>,
}

impl LinkNode {
    /// Creates a new link node.
    pub fn new(cfg: LinkConfig) -> anyhow::Result<Self> {
        let (send_incoming, recv_incoming) = smol::channel::unbounded();
        let client_id = if cfg.relay_config.is_some() {
            0
        } else {
            rand::random()
        };
        let graph = NetGraph::new(if let Some((identity, _)) = &cfg.relay_config {
            NeighborId::Relay(identity.public().fingerprint())
        } else {
            NeighborId::Client(client_id)
        });
        let process = if let Some((identity, in_routes)) = &cfg.relay_config {
            either::Either::Left(
                RelayProcess::new(
                    *identity,
                    in_routes.clone(),
                    cfg.out_routes.clone(),
                    graph.clone(),
                    cfg.exit_info.clone(),
                    send_incoming,
                )
                .spawn_smolscale(),
            )
        } else {
            either::Either::Right(
                ClientProcess::new(
                    client_id,
                    cfg.out_routes.clone(),
                    graph.clone(),
                    send_incoming,
                )
                .spawn_smolscale(),
            )
        };

        Ok(Self {
            cfg,
            process,
            graph,
            recv_incoming,
            client_id,
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
            either::Either::Right(client) => {
                client.send(ClientMsg::Forward(raw_packet)).await?;
            }
        }
        anyhow::Ok(())
    }

    fn package_raw(
        &self,
        packet: InnerPacket,
        src: AnonEndpoint,
        dest_relay: RelayFingerprint,
    ) -> anyhow::Result<Box<RawPacketWithNext>> {
        let route = self
            .graph
            .get_peelers(dest_relay, self.cfg.privacy_config.max_peelers)?;
        let instructs = self.graph.generate_instructs(&route)?;
        let first_peeler = *route.first().context("empty route")?;
        let dest_opk = self
            .graph
            .read_graph(|g| g.identity(&dest_relay))
            .context(format!(
                "couldn't get the identity of the destination fp {dest_relay}"
            ))?
            .onion_pk;
        Ok(Box::new(RawPacketWithNext {
            packet: RawPacket::new_normal(
                &instructs,
                &dest_opk,
                packet,
                earendil_crypt::RemoteId::Anon(src),
                self.cfg.privacy_config,
            )?,
            next_peeler: first_peeler,
        }))
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
    pub fn new_surb(&self, my_anon_id: AnonEndpoint) -> anyhow::Result<(Surb, ReplyDegarbler)> {
        let surb_dest = self.surb_destination()?;
        let reverse_route = self
            .graph
            .get_peelers(surb_dest, self.cfg.privacy_config.max_peelers)?;
        let reverse_instructs = self.graph.generate_instructs(&reverse_route)?;
        let dest_opk = self
            .graph
            .read_graph(|g| g.identity(&surb_dest))
            .context(format!(
                "destination {surb_dest} is surprisingly not in our RelayGraph"
            ))?
            .onion_pk;
        let (surb, degarbler) = Surb::new(
            &reverse_instructs,
            reverse_route[0],
            &dest_opk,
            self.client_id,
            my_anon_id,
            self.cfg.privacy_config,
        )
        .context("cannot build reply block")?;
        Ok((surb, degarbler))
    }

    fn surb_destination(&self) -> anyhow::Result<RelayFingerprint> {
        match &self.cfg.relay_config {
            Some(val) => Ok(val.0.public().fingerprint()),
            None => Ok(*self
                .graph
                .usable_relay_neighbors()
                .choose(&mut rand::thread_rng())
                .context("no relay neighbors to act as a SURB destination")?),
        }
    }

    /// Receives an incoming message. Blocks until we have something that's for us, and not to be forwarded elsewhere.
    pub async fn recv(&self) -> IncomingMsg {
        self.recv_incoming.recv().await.unwrap()
    }

    /// Gets the current relay graph.
    pub fn relay_graph(&self) -> RelayGraph {
        self.graph.read_graph(|g| g.clone())
    }

    /// Gets all our currently connected neighbors.
    pub fn all_neighs(&self) -> Vec<NeighborId> {
        todo!()
    }

    /// Sends a chat message to a neighbor.
    pub async fn send_chat(&self, _neighbor: NeighborId, _text: String) -> anyhow::Result<()> {
        todo!()
    }

    /// Gets the entire chat history with a neighbor.
    pub async fn get_chat_history(&self, _neighbor: NeighborId) -> anyhow::Result<Vec<ChatEntry>> {
        todo!()
    }

    pub async fn get_chat_summary(&self) -> anyhow::Result<Vec<(NeighborId, ChatEntry, u32)>> {
        todo!()
    }

    pub async fn get_debt_summary(&self) -> anyhow::Result<HashMap<String, f64>> {
        todo!()
    }

    pub async fn get_debt(&self, _neighbor: NeighborId) -> anyhow::Result<f64> {
        todo!()
    }

    pub async fn timeseries_stats(&self, _key: String, _start: i64, _end: i64) -> Vec<(i64, f64)> {
        todo!()
    }
}
