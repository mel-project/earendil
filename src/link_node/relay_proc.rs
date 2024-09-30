use std::{
    cell::OnceCell,
    collections::BTreeMap,
    convert::Infallible,
    sync::Arc,
    time::{Duration, Instant},
};

use ahash::AHashSet;
use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use earendil_crypt::{RelayFingerprint, RelayIdentitySecret, RemoteId};
use earendil_packet::{
    crypt::DhSecret, InnerPacket, Message, PeeledPacket, RawPacket, RawPacketWithNext, Surb,
};
use earendil_topology::{AdjacencyDescriptor, ExitInfo, IdentityDescriptor, RelayGraph};
use haiyuu::Handle;
use itertools::Itertools as _;
use moka::future::Cache;
use nanorpc::{JrpcRequest, JrpcResponse, RpcService};
use parking_lot::RwLock;
use smol::{channel::Sender, future::FutureExt as _};
use stdcode::StdcodeSerializeExt as _;

use crate::{
    config::{InRouteConfig, OutRouteConfig},
    link_node::switch_proc::SwitchMessage,
};

use super::{
    gossip::graph_gossip_loop,
    link_protocol::{InfoResponse, LinkProtocol, LinkRpcErr, LinkService},
    switch_proc::SwitchProcess,
    IncomingMsg,
};

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
    exit_info: Option<ExitInfo>,
    send_incoming: Sender<IncomingMsg>,
}

impl RelayProcess {
    /// Create a new relay process.
    pub fn new(
        identity: RelayIdentitySecret,
        in_routes: BTreeMap<String, InRouteConfig>,
        out_routes: BTreeMap<String, OutRouteConfig>,
        relay_graph: Arc<RwLock<RelayGraph>>,
        exit_info: Option<ExitInfo>,
        send_incoming: Sender<IncomingMsg>,
    ) -> Self {
        Self {
            identity,
            peel_secret: DhSecret::generate(),
            switch: OnceCell::new(),
            in_routes,
            out_routes,

            peel_dedup: AHashSet::new(),
            relay_graph,
            delay_queue: BTreeMap::new(),

            next_hop_cache: Cache::builder()
                .time_to_live(Duration::from_secs(60))
                .build(),

            exit_info,

            send_incoming,
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
                PeeledPacket::Received { from, pkt } => {
                    let _ = self
                        .send_incoming
                        .try_send(IncomingMsg::Forward { from, body: pkt });
                }
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
            switch
                .send(SwitchMessage::ToRelay(
                    Bytes::copy_from_slice(bytemuck::bytes_of(&packet)),
                    next_hop,
                ))
                .await?;
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
        let server = LinkService(LinkProtocolImpl {
            identity: self.identity,
            relay_graph: self.relay_graph.clone(),
        });
        let _gossip_loop = smolscale::spawn(graph_gossip_loop(
            Some(self.identity),
            self.relay_graph.clone(),
            self.switch.get().unwrap().downgrade(),
        ));

        let _identity_refresh_loop = {
            let exit_info = self.exit_info.clone();
            let graph = self.relay_graph.clone();
            let identity = self.identity;
            let peel_secret = self.peel_secret.clone();
            smolscale::spawn(async move {
                loop {
                    let myself =
                        IdentityDescriptor::new(&identity, &peel_secret, exit_info.clone());
                    tracing::debug!(
                        "inserting ourselves: {} into relay graph with exit: {:?}",
                        identity.public().fingerprint(),
                        exit_info
                    );
                    graph
                        .write()
                        .insert_identity(myself)
                        .expect("could not insert ourselves");
                    smol::Timer::after(Duration::from_secs(1)).await;
                }
            })
        };

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
                RelayMsg::LinkRpc(req, send) => {
                    let resp = server.respond_raw(req).await;
                    let _ = send.send(resp);
                }
                RelayMsg::Backwards(surb, msg) => {
                    let packet = RawPacket::new_reply(
                        &surb,
                        InnerPacket::Message(msg),
                        &RemoteId::Relay(self.identity.public().fingerprint()),
                    )
                    .expect("could not construct backwards packet");
                    if let Err(err) = self
                        .process(RawPacketWithNext {
                            packet,
                            next_peeler: surb.first_peeler,
                        })
                        .await
                    {
                        tracing::warn!(
                            err = debug(err),
                            "failed to forward a backwards packet we constructed"
                        );
                    }
                }
            }
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub enum RelayMsg {
    PeelForward(RawPacketWithNext),
    Backwards(Surb, Message),
    LinkRpc(JrpcRequest, oneshot::Sender<JrpcResponse>),
}

struct LinkProtocolImpl {
    identity: RelayIdentitySecret,
    relay_graph: Arc<RwLock<RelayGraph>>,
}

#[async_trait]
impl LinkProtocol for LinkProtocolImpl {
    /// A method that returns some random info. Used for keepalive and statistics.
    async fn info(&self) -> InfoResponse {
        InfoResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Asks the other end to complete an adjacency descriptor. Returns None to indicate refusal. This is called by the "left-hand" neighbor to ask the "right-hand" neighbor to sign.
    async fn sign_adjacency(
        &self,
        mut left_incomplete: AdjacencyDescriptor,
    ) -> Option<AdjacencyDescriptor> {
        let my_fp = self.identity.public().fingerprint();
        // This must be a neighbor that is "left" of us
        let valid = left_incomplete.left < left_incomplete.right
            && left_incomplete.right == my_fp
            && left_incomplete.is_timely();
        if !valid {
            tracing::debug!("incomplete adjacency invalid! Refusing to sign adjacency x_x");
            return None;
        }

        // Fill in the right-hand-side
        let signature = self.identity.sign(left_incomplete.to_sign().as_bytes());
        left_incomplete.right_sig = signature;

        self.relay_graph
            .write()
            .insert_adjacency(left_incomplete.clone())
            .map_err(|e| {
                tracing::warn!("could not insert here: {:?}", e);
                e
            })
            .ok()?;
        Some(left_incomplete)
    }

    /// Gets the identity of a particular fingerprint. Returns None if that identity is not known to this node.
    async fn all_identities(&self) -> Vec<IdentityDescriptor> {
        let graph = self.relay_graph.read();
        graph
            .all_nodes()
            .filter_map(|fp| graph.identity(&fp))
            .collect()
    }

    /// Gets all the adjacency-descriptors adjacent to the given fingerprints. This is called repeatedly to eventually discover the entire graph.
    async fn all_adjacencies(&self) -> Vec<AdjacencyDescriptor> {
        let rg = self.relay_graph.read();
        rg.all_adjacencies().collect()
    }

    /// Send a chat message to the other end of the link.
    async fn push_chat(&self, msg: String) -> Result<(), LinkRpcErr> {
        todo!()
    }

    /// Gets a one-time token to use in payment proofs for anti-double-spending
    async fn get_ott(&self) -> Result<String, LinkRpcErr> {
        todo!()
    }

    async fn send_payment_proof(
        &self,
        amount: u64,
        paysystem_name: String,
        proof: String,
    ) -> Result<(), LinkRpcErr> {
        todo!()
    }
}
