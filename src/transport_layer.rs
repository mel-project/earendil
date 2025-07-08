mod route_util;

mod types;
use std::{collections::BTreeMap, sync::Arc, u8};

use anyhow::Context;
use earendil_lownet::{Datagram, LowNet, NodeIdentity};

use bytes::Bytes;
use earendil_crypt::{AnonEndpoint, RelayFingerprint, RemoteId};
use earendil_packet::{InnerPacket, Message, PrivacyConfig, RawPacket, ReplyDegarbler, Surb};
use earendil_topology::{NodeAddr, RelayGraph};
use route_util::{forward_route_to, route_to_instructs};
use stdcode::StdcodeSerializeExt;
use tap::Tap;
pub use types::{IncomingMsg, LinkConfig};

/// An implementation of the link-level interface.
pub struct TransportLayer {
    lownet: Arc<LowNet>,
    privacy: PrivacyConfig,
}

impl TransportLayer {
    /// Creates a new transport layer.
    pub fn new(cfg: LinkConfig) -> anyhow::Result<Self> {
        use earendil_lownet::LowNetConfig;

        let identity = if let Some((relay_id, _)) = &cfg.relay_config {
            NodeIdentity::Relay(*relay_id)
        } else {
            NodeIdentity::ClientBearer(rand::random())
        };

        let in_links = cfg
            .relay_config
            .as_ref()
            .map(|(_, routes)| routes.values().cloned().collect())
            .unwrap_or_default();

        let out_links = cfg.out_links.values().cloned().collect();

        let lownet = LowNet::new(LowNetConfig {
            in_links,
            out_links,
            identity,
            metadata: BTreeMap::new().tap_mut(|bt| {
                if let Some(val) = cfg.exit_info {
                    bt.insert("exit_info".into(), val.stdcode().into());
                }
            }),
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
                dest_addr: *route.first().context("no first peeler")?,
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
            *route.first().context("no first peeler")?,
            &opk,
            my_anon_id,
            self.privacy,
        )?;
        Ok((surb, id, deg))
    }

    /// Receives an incoming message. Blocks until we have something that's for us, and not to be forwarded elsewhere.
    pub async fn recv(&self) -> IncomingMsg {
        use earendil_packet::{PeeledPacket, RAW_PACKET_SIZE};
        loop {
            let dg = self.lownet.recv().await;
            if dg.payload.len() != RAW_PACKET_SIZE {
                tracing::warn!(
                    len = debug(dg.payload.len()),
                    "dropping packet of wrong length"
                );
                continue;
            }
            let raw: RawPacket = *bytemuck::from_bytes(&dg.payload);
            match raw.peel(self.lownet.topology().dh_secret()) {
                Ok(PeeledPacket::Relay {
                    next_peeler,
                    pkt,
                    delay_ms,
                }) => {
                    tracing::trace!(next_peeler = display(next_peeler), "go to next peeler");
                    let lownet = self.lownet.clone();
                    smolscale::spawn(async move {
                        smol::Timer::after(core::time::Duration::from_millis(delay_ms as u64))
                            .await;
                        lownet
                            .send(Datagram {
                                ttl: dg.ttl.saturating_sub(1),
                                dest_addr: next_peeler,
                                payload: bytemuck::bytes_of(&pkt).to_vec().into(),
                            })
                            .await;
                    })
                    .detach();
                }
                Ok(PeeledPacket::Received { from, pkt }) => {
                    return IncomingMsg::Forward { from, body: pkt };
                }
                Ok(PeeledPacket::GarbledReply { surb_id, pkt }) => {
                    return IncomingMsg::Backward {
                        rb_id: surb_id,
                        body: Bytes::copy_from_slice(&pkt),
                    };
                }
                Err(err) => {
                    tracing::warn!(err = debug(err), "unpeelable packet received");
                    continue;
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
    pub fn my_id(&self) -> NodeIdentity {
        self.lownet.topology().identity()
    }

    /// Gets all our currently connected neighbors.
    pub fn all_neighs(&self) -> Vec<NodeAddr> {
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
