use std::{
    cell::OnceCell,
    collections::BTreeMap,
    convert::Infallible,
    sync::Arc,
    time::{Duration, Instant},
};

use ahash::AHashSet;
use anyhow::Context;
use earendil_crypt::{RelayFingerprint, RelayIdentitySecret};
use earendil_packet::{crypt::DhSecret, PeeledPacket, RawPacketWithNext};
use earendil_topology::RelayGraph;
use haiyuu::Handle;
use moka::future::Cache;
use nanorpc::{JrpcRequest, JrpcResponse};
use parking_lot::RwLock;
use smol::future::FutureExt as _;
use stdcode::StdcodeSerializeExt as _;

use crate::{
    config::{InRouteConfig, OutRouteConfig},
    link_node::switch_proc::SwitchMessage,
};

use super::switch_proc::SwitchProcess;

pub struct RelayProcess {
    identity: RelayIdentitySecret,
    peel_secret: DhSecret,
    switch: OnceCell<Handle<SwitchProcess>>,

    in_routes: BTreeMap<String, InRouteConfig>,
    out_routes: BTreeMap<String, OutRouteConfig>,

    peel_dedup: AHashSet<blake3::Hash>,
    relay_graph: Arc<RwLock<RelayGraph>>,
    delay_queue: BTreeMap<Instant, RawPacketWithNext>,

    next_hop_cache: Cache<RelayFingerprint, RelayFingerprint>,
}

impl RelayProcess {
    /// Create a new relay process.
    pub fn new(
        identity: RelayIdentitySecret,
        in_routes: BTreeMap<String, InRouteConfig>,
        out_routes: BTreeMap<String, OutRouteConfig>,
    ) -> Self {
        Self {
            identity,
            peel_secret: DhSecret::generate(),
            switch: OnceCell::new(),
            in_routes,
            out_routes,

            peel_dedup: AHashSet::new(),
            relay_graph: Arc::new(RwLock::new(RelayGraph::new())),
            delay_queue: BTreeMap::new(),

            next_hop_cache: Cache::builder()
                .time_to_live(Duration::from_secs(60))
                .build(),
        }
    }

    /// Process a particular raw packet.
    async fn process(&mut self, packet: RawPacketWithNext) -> anyhow::Result<()> {
        tracing::debug!("received a packet to peel and forward");
        let packet_hash = blake3::hash(bytemuck::bytes_of(&packet.packet));
        if !self.peel_dedup.insert(packet_hash) {
            anyhow::bail!("already processed packet with hash {:?}", packet_hash)
        }

        let switch = self.switch.get().unwrap().clone();

        if packet.next_peeler == self.identity.public().fingerprint() {
            let peeled = packet
                .packet
                .peel(&self.peel_secret)
                .context("failed to peel")?;
            match peeled {
                PeeledPacket::Relay {
                    next_peeler,
                    pkt,
                    delay_ms,
                } => {
                    let emit_time = Instant::now() + Duration::from_millis(delay_ms as _);
                    self.delay_queue.insert(
                        emit_time,
                        RawPacketWithNext {
                            next_peeler,
                            packet: pkt,
                        },
                    );
                }
                PeeledPacket::Received { from, pkt } => todo!(),
                PeeledPacket::GarbledReply {
                    client_id,
                    rb_id,
                    pkt,
                } => switch.send_or_drop(SwitchMessage::ToClient(
                    (rb_id, pkt.to_vec()).stdcode().into(),
                    client_id,
                ))?,
            }
        } else {
            let next_hop = self
                .next_hop_cache
                .try_get_with(packet.next_peeler, async {
                    let (send, recv) = oneshot::channel();
                    switch.send(SwitchMessage::DumpRelays(send)).await?;
                    let neighbors = recv.await?;

                    // find the neighbor with the lowest hops to the destination
                    let graph = self.relay_graph.read();
                    let mut min_hops = usize::MAX;
                    let mut min_hop_neighbor = None;
                    for neighbor in neighbors {
                        let hops = graph
                            .find_shortest_path(&neighbor, &packet.next_peeler)
                            .map(|hps| hps.len())
                            .unwrap_or(usize::MAX);
                        if hops < min_hops {
                            min_hops = hops;
                            min_hop_neighbor = Some(neighbor);
                        }
                    }
                    min_hop_neighbor.ok_or_else(|| anyhow::anyhow!("no relay found"))
                })
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
            todo!()
        }
        anyhow::Ok(())
    }
}

impl haiyuu::Process for RelayProcess {
    type Message = RelayMsg;
    type Output = Infallible;

    async fn run(&mut self, mailbox: &mut haiyuu::Mailbox<Self>) -> Infallible {
        self.switch
            .set(
                SwitchProcess::new_relay(
                    self.identity,
                    mailbox.handle(),
                    self.in_routes.clone(),
                    self.out_routes.clone(),
                )
                .spawn_smolscale(),
            )
            .ok()
            .unwrap();
        loop {
            let get_delayed = async {
                if let Some((time, _)) = self.delay_queue.first_key_value() {
                    smol::Timer::at(*time).await;
                    tracing::debug!(time = debug(time), "generating a PeelForward for delayed");
                    RelayMsg::PeelForward(self.delay_queue.pop_first().unwrap().1)
                } else {
                    smol::future::pending().await
                }
            };
            match mailbox.recv().or(get_delayed).await {
                RelayMsg::PeelForward(packet) => {
                    if let Err(err) = self.process(packet).await {
                        tracing::warn!(err = debug(err), "failed to peel and forward");
                    }
                }
                RelayMsg::LinkRpc(_, _) => todo!(),
            }
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub enum RelayMsg {
    PeelForward(RawPacketWithNext),
    LinkRpc(JrpcRequest, oneshot::Sender<JrpcResponse>),
}
