mod gossip;
mod link;
mod link_protocol;
mod link_protocol_impl;
mod link_store;
mod payment_system;
mod route_util;
mod settlement;
mod types;

use link_protocol::LinkClient;
pub use link_store::*;
use melstructs::NetID;
use payment_system::{PaymentSystem, PaymentSystemSelector};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::{SocketAddr, ToSocketAddrs as _},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::Context as _;
use bytes::Bytes;
use clone_macro::clone;
use dashmap::DashMap;
use earendil_crypt::{AnonEndpoint, RelayFingerprint, RelayIdentitySecret, RemoteId};
use earendil_packet::{
    crypt::DhSecret, InnerPacket, Message, PeeledPacket, RawPacket, ReplyDegarbler, Surb,
};
use earendil_topology::{IdentityDescriptor, RelayGraph};
use futures::AsyncReadExt;
use itertools::Itertools;
use parking_lot::RwLock;
use picomux::PicoMux;
use sillad::{
    dialer::Dialer as _,
    listener::Listener,
    tcp::{TcpDialer, TcpListener},
    Pipe,
};
use smol::{
    channel::{Receiver, Sender},
    future::FutureExt as _,
};
use smolscale::immortal::{Immortal, RespawnStrategy};
use stdcode::StdcodeSerializeExt;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::{
    config::{InRouteConfig, ObfsConfig, OutRouteConfig, PriceConfig},
    link_node::route_util::{forward_route_to, one_hop_closer, route_to_instructs},
    pascal::{read_pascal, write_pascal},
};

use self::{
    gossip::gossip_once,
    link::{Link, LinkMessage},
    link_protocol::LinkService,
    link_protocol_impl::LinkProtocolImpl,
    types::{ClientId, NeighborId},
};
pub use payment_system::{Dummy, SupportedPaymentSystems};
use rand::prelude::*;

/// An implementation of the link-level interface.
pub struct LinkNode {
    ctx: LinkNodeCtx,
    _task: Immortal,
    send_raw: Sender<LinkMessage>,
    recv_incoming: Receiver<IncomingMsg>,
}

impl LinkNode {
    /// Creates a new link node.
    pub fn new(mut cfg: LinkConfig, mel_client: melprot::Client) -> Self {
        let (send_raw, recv_raw) = smol::channel::bounded(1);
        let (send_incoming, recv_incoming) = smol::channel::bounded(1);
        let store = smolscale::block_on(LinkStore::new(cfg.db_path.clone())).unwrap();
        let relay_graph = match smol::future::block_on(store.get_misc("relay-graph"))
            .ok()
            .flatten()
            .and_then(|s| stdcode::deserialize(&s).ok())
        {
            Some(graph) => graph,
            None => RelayGraph::new(),
        };
        let my_id = if let Some((idsk, _)) = cfg.relay_config.clone() {
            LinkNodeId::Relay(idsk)
        } else {
            // I am a client with a persistent ClientId
            let mut rng = rand::thread_rng();
            let new_client_id = rng.gen_range(1..u64::MAX);
            let client_id = smol::future::block_on(
                store.get_or_insert_misc("my-client-id", new_client_id.to_le_bytes().to_vec()),
            )
            .map(|s| {
                let arr = s.try_into().expect("slice with incorrect length");
                u64::from_le_bytes(arr)
            })
            .unwrap();
            LinkNodeId::Client(client_id)
        };
        let mut payment_systems = PaymentSystemSelector::new();
        for payment_system in cfg.payment_systems.drain(..) {
            payment_systems.insert(payment_system);
        }
        let ctx = LinkNodeCtx {
            cfg: Arc::new(cfg),
            my_id,
            relay_graph: Arc::new(RwLock::new(relay_graph)),
            my_onion_sk: DhSecret::generate(),
            link_table: Arc::new(DashMap::new()),
            store: Arc::new(store),
            payment_systems: Arc::new(payment_systems),
            mel_client,
        };
        let _task = Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([ctx, send_raw, recv_raw], move || link_node_loop(
                ctx.clone(),
                send_raw.clone(),
                recv_raw.clone(),
                send_incoming.clone(),
            )),
        );
        Self {
            ctx,
            send_raw,
            recv_incoming,
            _task,
        }
    }

    /// Sends a "forward" packet, which could be either a message or a batch of reply blocks.
    pub async fn send_forward(
        &self,
        packet: InnerPacket,
        src: AnonEndpoint,
        dest_relay: RelayFingerprint,
    ) -> anyhow::Result<()> {
        let (first_peeler, wrapped_onion) = {
            let relay_graph = self.ctx.relay_graph.read();
            let route = forward_route_to(&relay_graph, dest_relay)
                .context("failed to create forward route")?;
            tracing::trace!("route to {dest_relay}: {:?}", route);
            let first_peeler = *route
                .first()
                .context("empty route, cannot obtain first peeler")?;

            let instructs =
                route_to_instructs(&relay_graph, &route).context("route_to_instructs failed")?;

            let dest_opk = relay_graph
                .identity(&dest_relay)
                .context(format!(
                    "couldn't get the identity of the destination fp {dest_relay}"
                ))?
                .onion_pk;

            (
                first_peeler,
                RawPacket::new_normal(&instructs, &dest_opk, packet, RemoteId::Anon(src))?,
            )
        };

        // send the raw packet
        self.send_raw(wrapped_onion, first_peeler).await;
        Ok(())
    }

    /// Sends a "backwards" packet, which consumes a reply block.
    pub async fn send_backwards(&self, reply_block: Surb, message: Message) -> anyhow::Result<()> {
        if let LinkNodeId::Relay(my_idsk) = self.ctx.my_id {
            let packet = RawPacket::new_reply(
                &reply_block,
                InnerPacket::Message(message.clone()),
                &RemoteId::Relay(my_idsk.public().fingerprint()),
            )?;
            self.send_raw(packet, reply_block.first_peeler).await;
            Ok(())
        } else {
            anyhow::bail!("we must be a relay to send backwards packets")
        }
    }

    /// Constructs a reply block back from the given relay.
    pub fn surb_from(
        &self,
        my_anon_id: AnonEndpoint,
        _remote: RelayFingerprint, // will use in the future for finding more efficient routes
    ) -> anyhow::Result<(Surb, u64, ReplyDegarbler)> {
        let destination = if let LinkNodeId::Relay(my_idsk) = self.ctx.my_id {
            my_idsk.public().fingerprint()
        } else {
            let mut lala = self.ctx.cfg.out_routes.values().collect_vec();
            lala.shuffle(&mut rand::thread_rng());
            lala.first().context("no out routes")?.fingerprint
        };
        let graph = self.ctx.relay_graph.read();
        let dest_opk = graph
            .identity(&destination)
            .context(format!(
                "destination {destination} is surprisingly not in our RelayGraph"
            ))?
            .onion_pk;
        let reverse_route = forward_route_to(&graph, destination)?;
        let reverse_instructs = route_to_instructs(&graph, &reverse_route)?;
        let my_client_id = match self.ctx.my_id {
            LinkNodeId::Relay(_) => 0, // special ClientId for relays
            LinkNodeId::Client(id) => id,
        };
        let (surb, (id, degarbler)) = Surb::new(
            &reverse_instructs,
            reverse_route[0],
            &dest_opk,
            my_client_id,
            my_anon_id,
        )
        .context("cannot build reply block")?;
        Ok((surb, id, degarbler))
    }

    /// Sends a raw packet.
    async fn send_raw(&self, raw: RawPacket, next_peeler: RelayFingerprint) {
        self.send_raw
            .send(LinkMessage::ToRelay {
                packet: bytemuck::bytes_of(&raw).to_vec().into(),
                next_peeler,
            })
            .await
            .unwrap();
    }

    /// Receives an incoming message. Blocks until we have something that's for us, and not to be forwarded elsewhere.
    pub async fn recv(&self) -> IncomingMsg {
        self.recv_incoming.recv().await.unwrap()
    }

    /// Gets all the currently known relays.
    pub fn all_relays(&self) -> Vec<RelayFingerprint> {
        self.ctx.relay_graph.read().all_nodes().collect_vec()
    }

    pub async fn send_chat(&self, neighbor: NeighborId, text: String) -> anyhow::Result<()> {
        let link_entry = self
            .ctx
            .link_table
            .get(&neighbor)
            .context(format!("not connected to neighbor {:?}", neighbor))?;
        LinkClient(link_entry.0.rpc_transport())
            .push_chat(text.clone())
            .await??;
        self.ctx
            .store
            .insert_chat_entry(
                neighbor,
                ChatEntry {
                    text,
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                    is_outgoing: true,
                },
            )
            .await?;
        Ok(())
    }

    pub async fn get_chat_history(&self, neighbor: NeighborId) -> anyhow::Result<Vec<ChatEntry>> {
        self.ctx.store.get_chat_history(neighbor).await
    }
}

/// Incoming messages from the link layer that are addressed to "us".
#[derive(Debug)]
pub enum IncomingMsg {
    Forward {
        from: AnonEndpoint,
        body: InnerPacket,
    },
    Backward {
        rb_id: u64,
        body: Bytes,
    },
}

#[derive(Clone)]
enum LinkNodeId {
    Relay(RelayIdentitySecret),
    Client(ClientId),
}

#[derive(Clone, Serialize, Deserialize)]
struct LinkPaymentInfo {
    price: i64,
    debt_limit: i64,
    paysystem_name_addrs: Vec<(String, String)>,
}

#[derive(Clone)]
struct LinkNodeCtx {
    cfg: Arc<LinkConfig>,
    my_id: LinkNodeId,
    my_onion_sk: DhSecret,
    relay_graph: Arc<RwLock<RelayGraph>>,
    link_table: Arc<DashMap<NeighborId, (Arc<Link>, LinkPaymentInfo)>>,
    payment_systems: Arc<PaymentSystemSelector>,
    store: Arc<LinkStore>,
    mel_client: melprot::Client,
}

#[tracing::instrument(skip_all)]
async fn link_node_loop(
    link_node_ctx: LinkNodeCtx,
    send_raw: Sender<LinkMessage>,
    recv_raw: Receiver<LinkMessage>,
    send_incoming: Sender<IncomingMsg>,
) -> anyhow::Result<()> {
    // ----------------------- helper closures ------------------------
    let link_node_ctx_clone = link_node_ctx.clone();
    let send_to_nonself_next_peeler =
        |emit_time: Option<Instant>, next_peeler: RelayFingerprint, pkt: RawPacket| {
            let closer_hop = {
                let graph = link_node_ctx_clone.relay_graph.read();
                let my_neighs = link_node_ctx_clone
                    .link_table
                    .iter()
                    .map(|p| *p.key())
                    .filter_map(|p| match p {
                        NeighborId::Relay(r) => Some(r),
                        NeighborId::Client(_) => None,
                    })
                    .collect_vec();
                one_hop_closer(&my_neighs, &graph, next_peeler)?
            };
            tracing::trace!("sending peeled packet to nonself next_peeler = {next_peeler}");
            let link = link_node_ctx_clone
                .link_table
                .get(&NeighborId::Relay(closer_hop))
                .context("cannot find closer hop")?
                .clone();
            // TODO delay queue here rather than this inefficient approach
            smolscale::spawn(async move {
                if let Some(emit_time) = emit_time {
                    smol::Timer::at(emit_time).await;
                }
                link.0
                    .send_msg(LinkMessage::ToRelay {
                        packet: bytemuck::bytes_of(&pkt).to_vec().into(),
                        next_peeler,
                    })
                    .await?;
                anyhow::Ok(())
            })
            .detach();
            anyhow::Ok(())
        };

    let send_to_next_peeler = |emit_time: Option<Instant>,
                               next_peeler: RelayFingerprint,
                               pkt: RawPacket,
                               send_raw: Sender<LinkMessage>,
                               my_fp: RelayFingerprint| {
        if next_peeler == my_fp {
            tracing::trace!("sending peeled packet to self = next_peeler");
            smolscale::spawn(async move {
                if let Some(emit_time) = emit_time {
                    smol::Timer::at(emit_time).await;
                }
                send_raw
                    .send(LinkMessage::ToRelay {
                        packet: bytemuck::bytes_of(&pkt).to_vec().into(),
                        next_peeler,
                    })
                    .await?;
                anyhow::Ok(())
            })
            .detach();
        } else {
            send_to_nonself_next_peeler(emit_time, next_peeler, pkt)?;
        }
        anyhow::Ok(())
    };

    // ----------------------- client + relay loops ------------------------
    let save_relay_graph_loop = async {
        loop {
            // println!("syncing DB...");
            let relay_graph = link_node_ctx_clone.relay_graph.read().stdcode();
            match link_node_ctx_clone
                .store
                .insert_misc("relay_graph".to_string(), relay_graph)
                .await
            {
                Ok(_) => (),
                Err(e) => tracing::warn!("saving relay graph failed with: {e}"),
            };
            smol::Timer::after(Duration::from_secs(10)).await;
        }
    };

    let out_task = async {
        if link_node_ctx_clone.cfg.out_routes.is_empty() {
            smol::future::pending().await
        } else {
            futures_util::future::try_join_all(link_node_ctx_clone.cfg.out_routes.iter().map(
                |(name, out_route)| {
                    process_out_route(
                        link_node_ctx_clone.clone(),
                        name,
                        out_route,
                        send_raw.clone(),
                    )
                },
            ))
            .await
        }
    };

    // ----------------------- relay-only loops ------------------------
    let relay_or_client_task = async {
        if let LinkNodeId::Relay(my_idsk) = link_node_ctx.my_id {
            let identity_refresh_loop = async {
                loop {
                    // println!("WE ARE INSERTING OURSELVES");
                    let myself =
                        IdentityDescriptor::new(&my_idsk, &link_node_ctx_clone.my_onion_sk);
                    link_node_ctx_clone
                        .relay_graph
                        .write()
                        .insert_identity(myself)?;
                    smol::Timer::after(Duration::from_secs(1)).await;
                }
            };

            let in_task = async {
                if let Some((_, in_routes)) = link_node_ctx.cfg.relay_config.clone() {
                    if !in_routes.is_empty() {
                        futures_util::future::try_join_all(in_routes.iter().map(
                            |(name, in_route)| {
                                process_in_route(
                                    link_node_ctx.clone(),
                                    name,
                                    in_route,
                                    send_raw.clone(),
                                )
                            },
                        ))
                        .await
                    } else {
                        smol::future::pending().await
                    }
                } else {
                    smol::future::pending().await
                }
            };

            let relay_peel_loop = async {
                loop {
                    let fallible = async {
                        match recv_raw.recv().await? {
                            LinkMessage::ToRelay {
                                packet,
                                next_peeler,
                            } => {
                                tracing::trace!(
                                    "{:?} received incoming linkmsg ToRelay. next_peeler = {next_peeler}",
                                    my_idsk.public().fingerprint()
                                );
                                let packet: &RawPacket = bytemuck::try_from_bytes(&packet)
                                    .ok()
                                    .context("could not cast")?;

                                // relay pkt
                                if next_peeler != my_idsk.public().fingerprint() {
                                    // forward pkt without delay
                                    send_to_nonself_next_peeler(None, next_peeler, *packet)?
                                } else {
                                    // tracing::debug!(
                                    //     next_peeler = display(next_peeler),
                                    //     "I am the designated peeler"
                                    // );
                                    // let now = Instant::now();
                                    let peeled: PeeledPacket =
                                        packet.peel(&link_node_ctx.my_onion_sk)?;
                                    // tracing::trace!("message peel took {:?}", now.elapsed());
                                    match peeled {
                                        PeeledPacket::Relay {
                                            next_peeler,
                                            pkt,
                                            delay_ms,
                                        } => {
                                            tracing::trace!(
                                                "received a PeeledPacket::Relay for next_peeler = {next_peeler}"
                                            );
                                            let emit_time = Instant::now()
                                                + Duration::from_millis(delay_ms as u64);
                                            send_to_next_peeler(
                                                Some(emit_time),
                                                next_peeler,
                                                pkt,
                                                send_raw.clone(),
                                                my_idsk.public().fingerprint(),
                                            )?;
                                        }
                                        PeeledPacket::Received { from, pkt } => {
                                            tracing::trace!(
                                                "received a PeeledPacket::Received from = {from}"
                                            );
                                            send_incoming
                                                .send(IncomingMsg::Forward { from, body: pkt })
                                                .await?;
                                        }
                                        PeeledPacket::GarbledReply {
                                            rb_id,
                                            pkt,
                                            client_id,
                                        } => {
                                            if client_id == 0 {
                                                tracing::trace!(
                                                    rb_id = rb_id,
                                                    "received a PeeledPacket::GarbledReply for MYSELF"
                                                );
                                                send_incoming
                                                    .send(IncomingMsg::Backward {
                                                        rb_id,
                                                        body: pkt.to_vec().into(),
                                                    })
                                                    .await?;
                                            } else {
                                                tracing::trace!(
                                                    rb_id,
                                                    client_id,
                                                    "received a PeeledPacket::GarbledReply for a CLIENT"
                                                );
                                                let table = link_node_ctx.link_table.clone();
                                                smolscale::spawn(async move {
                                                    // I send pkt to downstream client; charge money
                                                    table
                                                        .get(&NeighborId::Client(client_id))
                                                        .context("no such client")?
                                                        .0
                                                        .send_msg(LinkMessage::ToClient {
                                                            body: pkt.to_vec().into(),
                                                            rb_id,
                                                        })
                                                        .await?;
                                                    anyhow::Ok(())
                                                })
                                                .detach();
                                            }
                                        }
                                    }
                                }
                            }
                            LinkMessage::ToClient { body: _, rb_id: _ } => {
                                anyhow::bail!("Relay received LinkMessage::ToClient")
                            }
                        }
                        anyhow::Ok(())
                    };
                    if let Err(err) = fallible.await {
                        tracing::error!(err = debug(err), "error in relay_peel_loop");
                    }
                }
            };

            identity_refresh_loop
                .race(in_task)
                .race(relay_peel_loop)
                .await
        } else {
            let client_peel_loop = async {
                loop {
                    let fallible = async {
                        match recv_raw.recv().await? {
                            LinkMessage::ToRelay {
                                packet,
                                next_peeler,
                            } => {
                                let packet: &RawPacket = bytemuck::try_from_bytes(&packet)
                                    .ok()
                                    .context("could not cast")?;
                                send_to_nonself_next_peeler(None, next_peeler, *packet)?
                            }
                            LinkMessage::ToClient { body, rb_id } => {
                                send_incoming
                                    .send(IncomingMsg::Backward { rb_id, body })
                                    .await?;
                            }
                        }
                        anyhow::Ok(())
                    };
                    if let Err(err) = fallible.await {
                        tracing::error!(err = debug(err), "error in client_peel_loop");
                    }
                }
            };
            client_peel_loop.await
        }
    };

    match relay_or_client_task // loops specific to relay or client
        .race(out_task) // for both relay + client
        .race(save_relay_graph_loop) // for both relay + client
        .await
    {
        Ok(_) => tracing::warn!("link_node_loop() returned?"),
        Err(e) => tracing::error!("link_loop() error: {e}"),
    }
    Ok(())
}

// let LinkPaymentInfo {
//     price,
//     debt_limit,
//     accepted_payment_methods,
// } = serde_json::from_slice(msg_stream.metadata())?;
// // check if price < our max_price
// let pay_dest;
// if price < outroute_config.max_price {
//     // check if any of our pay_methods ∈ their supported methods
//     for pay_method in payment_methods.get_available() {
//         if accepted_payment_methods
//             .get_available()
//             .contains(&pay_method)
//         {
//             // construct impl PaymentDestination & save to link
//             match pay_method {
//                 PaymentMethod::Dummy => {
//                     pay_dest = Box::new(DummyPayDest);
//                     break;
//                 }
//             }
//         }
//     }
//     anyhow::bail!("no supported payment method")
// } else {
//     anyhow::bail!("price too high")
// };
// // fns for when I'm upstream
// async fn incr_debt(&self) -> anyhow::Result<()> {
//     let (neighbor, delta) = match &self.payment_info {
//         PaymentInfo::InRoute(info) => (
//             NeighborId::Client(info.their_client_id),
//             -info.inroute_config.price,
//         ),
//         PaymentInfo::OutRoute(info) => (
//             NeighborId::Relay(info.outroute_config.fingerprint),
//             info.price,
//         ),
//     };
//     let debt_entry = DebtEntry {
//         delta,
//         timestamp: SystemTime::now()
//             .duration_since(UNIX_EPOCH)
//             .expect("Time went backwards")
//             .as_secs(),
//         proof: None,
//     };
//     self.store.insert_debt_entry(neighbor, debt_entry).await?;
//     Ok(())
// }

// async fn is_within_debt_limit(&self) -> anyhow::Result<bool> {
//     todo!()
// }

// async fn decr_debt(&self, proof: Proof) -> anyhow::Result<()> {
//     todo!()
// }

// async fn pay_debt(&self) -> anyhow::Result<()> {
//     todo!()
// }

async fn process_in_route(
    link_node_ctx: LinkNodeCtx,
    name: &str,
    in_route: &InRouteConfig,
    send_raw: Sender<LinkMessage>,
) -> anyhow::Result<()> {
    let mut listener = TcpListener::bind(in_route.listen).await?;
    match &in_route.obfs {
        ObfsConfig::None => loop {
            let pipe = listener.accept().await?;
            tracing::debug!(
                name,
                remote_addr = debug(pipe.remote_addr()),
                "accepted a TCP connection"
            );
            smolscale::spawn(handle_pipe(
                link_node_ctx.clone(),
                pipe,
                send_raw.clone(),
                RouteConfig::In(in_route.clone()),
            ))
            .detach();
        },
        ObfsConfig::Sosistab3(_) => todo!(),
    }
}

async fn process_out_route(
    link_node_ctx: LinkNodeCtx,
    name: &str,
    out_route: &OutRouteConfig,
    send_raw: Sender<LinkMessage>,
) -> anyhow::Result<()> {
    loop {
        let fallible = async {
            let dest_addr = if let Ok(socket_addr) = out_route.connect.parse() {
                socket_addr
            } else {
                let addrs: Vec<SocketAddr> = out_route
                    .connect
                    .clone()
                    .to_socket_addrs()
                    .map(|iter| iter.collect())
                    .map_err(|e| {
                        anyhow::anyhow!("unable to resolve domain {}: {}", &out_route.connect, e)
                    })?;
                let addr = addrs.first().context("empty list of resolved domains")?;

                *addr
            };
            let tcp_dialer = TcpDialer { dest_addr };
            match &out_route.obfs {
                ObfsConfig::None => {
                    let tcp_pipe = tcp_dialer.dial().await?;
                    tracing::debug!(name, "TCP connected to other side");
                    handle_pipe(
                        link_node_ctx.clone(),
                        tcp_pipe,
                        send_raw.clone(),
                        RouteConfig::Out(out_route.clone()),
                    )
                    .await
                }
                ObfsConfig::Sosistab3(_cookie) => {
                    todo!()
                }
            }
        };
        if let Err(err) = fallible.await {
            tracing::warn!(
                err = debug(err),
                connect = debug(&out_route.connect),
                "restarting out route"
            );
        }
        smol::Timer::after(Duration::from_secs(1)).await;
    }
}

/// impl Pipe -> Mux -> Link
#[derive(Clone)]
enum RouteConfig {
    Out(OutRouteConfig),
    In(InRouteConfig),
}

async fn handle_pipe(
    link_node_ctx: LinkNodeCtx,
    pipe: impl Pipe,
    send_raw: Sender<LinkMessage>,
    route_config: RouteConfig,
) -> anyhow::Result<()> {
    let (link, their_descr, payment_info) = match route_config.clone() {
        RouteConfig::Out(config) => {
            let (mux, their_descr, payment_info) =
                pipe_to_mux(&link_node_ctx, pipe, config.price_config).await?;
            (
                Arc::new(Link::new_dial(mux).await?),
                their_descr,
                payment_info,
            )
        }
        RouteConfig::In(config) => {
            let (mux, their_descr, payment_info) =
                pipe_to_mux(&link_node_ctx, pipe, config.price_config).await?;
            (
                Arc::new(Link::new_listen(mux).await?),
                their_descr,
                payment_info,
            )
        }
    };

    // insert as either client or relay
    match their_descr.clone() {
        LinkNodeDescr::Relay(descr) => link_node_ctx.link_table.insert(
            NeighborId::Relay(descr.identity_pk.fingerprint()),
            (link.clone(), payment_info),
        ),
        LinkNodeDescr::Client(id) => link_node_ctx
            .link_table
            .insert(NeighborId::Client(id), (link.clone(), payment_info)),
    };

    let their_relay_fp = match their_descr.clone() {
        LinkNodeDescr::Relay(descr) => Some(descr.identity_pk.fingerprint()),
        LinkNodeDescr::Client(_) => None,
    };

    let their_id = match their_descr {
        LinkNodeDescr::Relay(descr) => NeighborId::Relay(descr.identity_pk.fingerprint()),
        LinkNodeDescr::Client(id) => NeighborId::Client(id),
    };

    let gossip_loop = async {
        loop {
            smol::Timer::after(Duration::from_secs(1)).await;
            if let Err(e) = gossip_once(&link_node_ctx, &link, their_relay_fp).await {
                tracing::warn!(err = debug(e), "gossip_once failed");
            };
        }
    };

    let rpc_serve_loop = link.rpc_serve(LinkService(LinkProtocolImpl {
        ctx: link_node_ctx.clone(),
        remote_id: their_id,
    }));

    // let route_config_clone = route_config.clone();

    gossip_loop
        .race(rpc_serve_loop)
        .race(
            // pull messages from the link
            async {
                loop {
                    let msg = link.recv_msg().await?;
                    tracing::trace!("received LinkMessage from {:?}", their_id);
                    // match route_config {
                    //     RouteConfig::Out(_) => {
                    //         // I receive pkt from my upstream
                    //         todo!()
                    //     },
                    //     RouteConfig::In(config) => {
                    //         // I receive pkt from my downstream
                    //         let neigh = NeighborId::Relay(their_relay_fp.unwrap());
                    //         // drop msg if debt > debt_limit
                    //         let debt = link_node_ctx.store.get_debt(neigh).await?;
                    //         if debt > config.debt_limit {
                    //             tracing::warn!(
                    //                 "DROPPING PACKET: {:?} is over their debt limit! debt={debt}; debt_limit={}",
                    //                 neigh,
                    //                 config.debt_limit
                    //             );
                    //             continue;
                    //         }
                    //         // increment remote's debt
                    //         link_node_ctx
                    //             .store
                    //             .insert_debt_entry(
                    //                 neigh,
                    //                 DebtEntry {
                    //                     delta: config.price as _,
                    //                     timestamp: SystemTime::now()
                    //                         .duration_since(UNIX_EPOCH)
                    //                         .expect("Time went backwards")
                    //                         .as_secs(),
                    //                     proof: None,
                    //                 },
                    //             )
                    //             .await?;
                    //     }
                    // }
                    send_raw.send(msg).await?;
                }
            },
        )
        .await
}

#[derive(Serialize, Deserialize, Debug, Clone)]
enum LinkNodeDescr {
    Relay(IdentityDescriptor),
    Client(ClientId),
}

async fn pipe_to_mux(
    link_node_ctx: &LinkNodeCtx,
    pipe: impl Pipe,
    price_config: PriceConfig,
) -> anyhow::Result<(PicoMux, LinkNodeDescr, LinkPaymentInfo)> {
    let (mut read, mut write) = pipe.split();
    let send_auth = async {
        let my_descr = match link_node_ctx.my_id {
            LinkNodeId::Relay(id) => {
                LinkNodeDescr::Relay(IdentityDescriptor::new(&id, &link_node_ctx.my_onion_sk))
            }
            LinkNodeId::Client(id) => LinkNodeDescr::Client(id),
        };
        let my_payment_info = LinkPaymentInfo {
            price: price_config.inbound_price,
            debt_limit: price_config.inbound_debt_limit,
            paysystem_name_addrs: link_node_ctx.payment_systems.get_available(),
        };
        let auth_msg = (my_descr, my_payment_info).stdcode();
        write_pascal(&auth_msg, &mut write).await?;
        anyhow::Ok(())
    };

    let recv_auth = async {
        let bts = read_pascal(&mut read).await?;
        let (their_descr, their_payinfo): (LinkNodeDescr, LinkPaymentInfo) =
            stdcode::deserialize(&bts)?;
        tracing::debug!(
            "their_price: {}; our_max_price: {}",
            their_payinfo.price,
            price_config.outbound_max_price
        );
        if their_payinfo.price < price_config.outbound_max_price {
            if link_node_ctx
                .payment_systems
                .select(&their_payinfo.paysystem_name_addrs)
                .is_some()
            {
                anyhow::Ok((their_descr, their_payinfo))
            } else {
                anyhow::bail!("{:?} no supported payment methods", their_descr)
            }
        } else {
            anyhow::bail!("{:?} price too high!", their_descr)
        }
    };

    let (a, b) = futures::join!(send_auth, recv_auth);
    a?;
    let (their_descr, their_payinfo) = b?;
    let mux = PicoMux::new(read, write);
    Ok((mux, their_descr, their_payinfo))
}

pub struct LinkConfig {
    pub relay_config: Option<(RelayIdentitySecret, BTreeMap<String, InRouteConfig>)>,
    pub out_routes: BTreeMap<String, OutRouteConfig>,
    pub payment_systems: Vec<Box<dyn PaymentSystem>>,
    pub db_path: PathBuf,
}

pub async fn get_two_connected_relays() -> (LinkNode, LinkNode) {
    let idsk1 = RelayIdentitySecret::generate();
    let mut in_1 = BTreeMap::new();
    in_1.insert(
        "1".to_owned(),
        InRouteConfig {
            listen: "127.0.0.1:30000".parse().unwrap(),
            obfs: ObfsConfig::None,
            price_config: PriceConfig {
                inbound_price: 5,
                inbound_debt_limit: 500,
                outbound_max_price: 10,
            },
        },
    );

    let idsk2 = RelayIdentitySecret::generate();
    let mut in_2 = BTreeMap::new();
    in_2.insert(
        "2".to_owned(),
        InRouteConfig {
            listen: "127.0.0.1:30001".parse().unwrap(),
            obfs: ObfsConfig::None,
            price_config: PriceConfig {
                inbound_price: 5,
                inbound_debt_limit: 500,
                outbound_max_price: 10,
            },
        },
    );
    let mut out_2 = BTreeMap::new();
    out_2.insert(
        "1".to_owned(),
        OutRouteConfig {
            connect: "127.0.0.1:30000".parse().unwrap(),
            fingerprint: idsk1.public().fingerprint(),
            obfs: ObfsConfig::None,
            price_config: PriceConfig {
                inbound_price: 5,
                inbound_debt_limit: 500,
                outbound_max_price: 10,
            },
        },
    );

    let node1 = LinkNode::new(
        LinkConfig {
            relay_config: Some((idsk1, in_1)),
            out_routes: BTreeMap::new(),
            db_path: {
                let mut path = tempfile::tempdir().unwrap().into_path();
                path.push(idsk1.public().fingerprint().to_string());
                path
            },
            payment_systems: vec![Box::new(Dummy::new())],
        },
        melprot::Client::autoconnect(NetID::Mainnet).await.unwrap(),
    );

    let node2 = LinkNode::new(
        LinkConfig {
            relay_config: Some((idsk2, in_2)),
            out_routes: out_2,
            db_path: {
                let mut path = tempfile::tempdir().unwrap().into_path();
                path.push(idsk2.public().fingerprint().to_string());
                path
            },
            payment_systems: vec![Box::new(Dummy::new())],
        },
        melprot::Client::autoconnect(NetID::Mainnet).await.unwrap(),
    );

    (node1, node2)
}

pub fn init_tracing() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().compact())
        .with(
            EnvFilter::builder()
                .with_default_directive("earendil=debug".parse()?)
                .from_env_lossy(),
        )
        .init();
    Ok(())
}

pub async fn get_connected_relay_client() -> (LinkNode, LinkNode) {
    let idsk1 = RelayIdentitySecret::generate();
    let mut in_1 = BTreeMap::new();
    in_1.insert(
        "1".to_owned(),
        InRouteConfig {
            listen: "127.0.0.1:30000".parse().unwrap(),
            obfs: ObfsConfig::None,
            price_config: PriceConfig {
                inbound_price: 5,
                inbound_debt_limit: 500,
                outbound_max_price: 10,
            },
        },
    );

    let mut out_2 = BTreeMap::new();
    out_2.insert(
        "1".to_owned(),
        OutRouteConfig {
            connect: "127.0.0.1:30000".parse().unwrap(),
            fingerprint: idsk1.public().fingerprint(),
            obfs: ObfsConfig::None,
            price_config: PriceConfig {
                inbound_price: 5,
                inbound_debt_limit: 500,
                outbound_max_price: 10,
            },
        },
    );

    let relay = LinkNode::new(
        LinkConfig {
            relay_config: Some((idsk1, in_1)),
            out_routes: BTreeMap::new(),
            db_path: {
                let mut path = tempfile::tempdir().unwrap().into_path();
                path.push(idsk1.public().fingerprint().to_string());
                path
            },
            payment_systems: vec![Box::new(Dummy::new())],
        },
        melprot::Client::autoconnect(NetID::Mainnet).await.unwrap(),
    );

    let client = LinkNode::new(
        LinkConfig {
            relay_config: None,
            out_routes: out_2,
            db_path: {
                let mut path = tempfile::tempdir().unwrap().into_path();
                path.push(
                    RelayIdentitySecret::generate()
                        .public()
                        .fingerprint()
                        .to_string(),
                );
                path
            },
            payment_systems: vec![Box::new(Dummy::new())],
        },
        melprot::Client::autoconnect(NetID::Mainnet).await.unwrap(),
    );

    (relay, client)
}

pub async fn get_four_connected_relays() -> (LinkNode, LinkNode, LinkNode, LinkNode) {
    let idsk1 = RelayIdentitySecret::generate();
    let mut in_1 = BTreeMap::new();
    in_1.insert(
        "1".to_owned(),
        InRouteConfig {
            listen: "127.0.0.1:30000".parse().unwrap(),
            obfs: ObfsConfig::None,
            price_config: PriceConfig {
                inbound_price: 5,
                inbound_debt_limit: 500,
                outbound_max_price: 10,
            },
        },
    );

    let idsk2 = RelayIdentitySecret::generate();
    let mut in_2 = BTreeMap::new();
    in_2.insert(
        "2".to_owned(),
        InRouteConfig {
            listen: "127.0.0.1:30001".parse().unwrap(),
            obfs: ObfsConfig::None,
            price_config: PriceConfig {
                inbound_price: 5,
                inbound_debt_limit: 500,
                outbound_max_price: 10,
            },
        },
    );
    let mut out_2 = BTreeMap::new();
    out_2.insert(
        "1".to_owned(),
        OutRouteConfig {
            connect: "127.0.0.1:30000".parse().unwrap(),
            fingerprint: idsk1.public().fingerprint(),
            obfs: ObfsConfig::None,
            price_config: PriceConfig {
                inbound_price: 5,
                inbound_debt_limit: 500,
                outbound_max_price: 10,
            },
        },
    );

    let idsk3 = RelayIdentitySecret::generate();
    let mut in_3 = BTreeMap::new();
    in_3.insert(
        "1".to_owned(),
        InRouteConfig {
            listen: "127.0.0.1:30002".parse().unwrap(),
            obfs: ObfsConfig::None,
            price_config: PriceConfig {
                inbound_price: 5,
                inbound_debt_limit: 500,
                outbound_max_price: 10,
            },
        },
    );
    let mut out_3 = BTreeMap::new();
    out_3.insert(
        "1".to_owned(),
        OutRouteConfig {
            connect: "127.0.0.1:30001".parse().unwrap(),
            fingerprint: idsk1.public().fingerprint(),
            obfs: ObfsConfig::None,
            price_config: PriceConfig {
                inbound_price: 5,
                inbound_debt_limit: 500,
                outbound_max_price: 10,
            },
        },
    );
    let idsk4 = RelayIdentitySecret::generate();
    let mut in_4 = BTreeMap::new();
    in_4.insert(
        "2".to_owned(),
        InRouteConfig {
            listen: "127.0.0.1:30003".parse().unwrap(),
            obfs: ObfsConfig::None,
            price_config: PriceConfig {
                inbound_price: 5,
                inbound_debt_limit: 500,
                outbound_max_price: 10,
            },
        },
    );
    let mut out_4 = BTreeMap::new();
    out_4.insert(
        "1".to_owned(),
        OutRouteConfig {
            connect: "127.0.0.1:30002".parse().unwrap(),
            fingerprint: idsk1.public().fingerprint(),
            obfs: ObfsConfig::None,
            price_config: PriceConfig {
                inbound_price: 5,
                inbound_debt_limit: 500,
                outbound_max_price: 10,
            },
        },
    );

    let node1 = LinkNode::new(
        LinkConfig {
            relay_config: Some((idsk1, in_1)),
            out_routes: BTreeMap::new(),
            db_path: {
                let mut path = tempfile::tempdir().unwrap().into_path();
                path.push(idsk1.public().fingerprint().to_string());
                path
            },
            payment_systems: vec![Box::new(Dummy::new())],
        },
        melprot::Client::autoconnect(NetID::Mainnet).await.unwrap(),
    );
    let node2 = LinkNode::new(
        LinkConfig {
            relay_config: Some((idsk2, in_2)),
            out_routes: out_2,
            db_path: {
                let mut path = tempfile::tempdir().unwrap().into_path();
                path.push(idsk2.public().fingerprint().to_string());
                path
            },
            payment_systems: vec![Box::new(Dummy::new())],
        },
        melprot::Client::autoconnect(NetID::Mainnet).await.unwrap(),
    );
    let node3 = LinkNode::new(
        LinkConfig {
            relay_config: Some((idsk3, in_3)),
            out_routes: out_3,
            db_path: {
                let mut path = tempfile::tempdir().unwrap().into_path();
                path.push(idsk3.public().fingerprint().to_string());
                path
            },
            payment_systems: vec![Box::new(Dummy::new())],
        },
        melprot::Client::autoconnect(NetID::Mainnet).await.unwrap(),
    );
    let node4 = LinkNode::new(
        LinkConfig {
            relay_config: Some((idsk4, in_4)),
            out_routes: out_4,
            db_path: {
                let mut path = tempfile::tempdir().unwrap().into_path();
                path.push(idsk4.public().fingerprint().to_string());
                path
            },
            payment_systems: vec![Box::new(Dummy::new())],
        },
        melprot::Client::autoconnect(NetID::Mainnet).await.unwrap(),
    );

    (node1, node2, node3, node4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use earendil_packet::RawBody;

    #[test]
    fn two_relays_one_forward_pkt() {
        let _ = init_tracing();

        let pkt = InnerPacket::Message(Message {
            relay_dock: 123,
            body: Bytes::from_static(b"lol"),
        });
        smol::block_on(async {
            smol::Timer::after(Duration::from_secs(3)).await;
            let (node1, node2) = get_two_connected_relays().await;
            node2
                .send_forward(
                    pkt.clone(),
                    AnonEndpoint::random(),
                    node1
                        .ctx
                        .cfg
                        .relay_config
                        .as_ref()
                        .unwrap()
                        .0
                        .public()
                        .fingerprint(), // we know node1 is a relay
                )
                .await
                .unwrap();
            match node1.recv().await {
                IncomingMsg::Forward { from: _, body } => {
                    assert_eq!(body, pkt);
                }
                IncomingMsg::Backward { rb_id: _, body: _ } => panic!("not supposed to happen"),
            }
        });
    }

    #[test]
    fn two_relays_one_backward_pkt() {
        let _ = init_tracing();

        smol::block_on(async {
            smol::Timer::after(Duration::from_secs(3)).await;
            let (node1, node2) = get_two_connected_relays().await;
            let (surb_1to2, surb_id, degarbler) = node2
                .surb_from(
                    AnonEndpoint::random(),
                    node1
                        .ctx
                        .cfg
                        .relay_config
                        .clone()
                        .unwrap()
                        .0
                        .public()
                        .fingerprint(),
                )
                .unwrap(); // we know that node1 is a relay
            println!("got surb");
            let msg_relay_dock = 123;
            let msg_body = Bytes::from_static(b"lol");
            node1
                .send_backwards(
                    surb_1to2,
                    Message {
                        relay_dock: msg_relay_dock,
                        body: msg_body.clone(),
                    },
                )
                .await
                .unwrap();
            println!("msg sent");
            match node2.recv().await {
                IncomingMsg::Forward { from: _, body: _ } => panic!("not supposed to happen"),
                IncomingMsg::Backward { rb_id, body } => {
                    assert_eq!(rb_id, surb_id);
                    let mut body: RawBody = *bytemuck::try_from_bytes(&body).unwrap();
                    let (inner_pkt, _) = degarbler.degarble(&mut body).unwrap();
                    match inner_pkt {
                        InnerPacket::Message(Message { relay_dock, body }) => {
                            assert_eq!(msg_body, body);
                            assert_eq!(msg_relay_dock, relay_dock);
                            println!("YAY SUCCESS")
                        }
                        InnerPacket::Surbs(_) => todo!(),
                    }
                }
            }
        })
    }

    #[test]
    fn client_relay_one_forward_pkt() {
        let _ = init_tracing();

        let pkt = InnerPacket::Message(Message {
            relay_dock: 123,
            body: Bytes::from_static(b"lol"),
        });

        smol::block_on(async {
            smol::Timer::after(Duration::from_secs(3)).await;
            let (relay_node, client_node) = get_connected_relay_client().await;
            match client_node
                .send_forward(
                    pkt.clone(),
                    AnonEndpoint::random(),
                    relay_node
                        .ctx
                        .cfg
                        .relay_config
                        .clone()
                        .unwrap()
                        .0
                        .public()
                        .fingerprint(), // we know node1 is a relay
                )
                .await
            {
                Ok(_) => println!("client --> relay LinkMsg sent"),
                Err(e) => println!("ERR sending client --> relay LinkMsfg: {e}"),
            }
            match relay_node.recv().await {
                IncomingMsg::Forward { from: _, body } => {
                    assert_eq!(body, pkt);
                }
                IncomingMsg::Backward { rb_id: _, body: _ } => panic!("not supposed to happen"),
            }
        });
    }

    #[test]
    fn client_relay_one_backward_pkt() {
        let _ = init_tracing();

        smol::block_on(async {
            smol::Timer::after(Duration::from_secs(3)).await;
            let (relay_node, client_node) = get_connected_relay_client().await;
            println!(
                "relay_node fp = {}",
                relay_node
                    .ctx
                    .cfg
                    .relay_config
                    .clone()
                    .unwrap()
                    .0
                    .public()
                    .fingerprint(),
            );
            let (surb_1to2, surb_id, degarbler) = client_node
                .surb_from(
                    AnonEndpoint::random(),
                    relay_node
                        .ctx
                        .cfg
                        .relay_config
                        .clone()
                        .unwrap()
                        .0
                        .public()
                        .fingerprint(),
                )
                .unwrap(); // we know that node1 is a relay
            println!("got surb");
            let msg_relay_dock = 123;
            let msg_body = Bytes::from_static(b"lol");
            relay_node
                .send_backwards(
                    surb_1to2,
                    Message {
                        relay_dock: msg_relay_dock,
                        body: msg_body.clone(),
                    },
                )
                .await
                .unwrap();
            println!("msg sent");
            match client_node.recv().await {
                IncomingMsg::Forward { from: _, body: _ } => panic!("not supposed to happen"),
                IncomingMsg::Backward { rb_id, body } => {
                    assert_eq!(rb_id, surb_id);
                    let mut body: RawBody = *bytemuck::try_from_bytes(&body).unwrap();
                    let (inner_pkt, _) = degarbler.degarble(&mut body).unwrap();
                    match inner_pkt {
                        InnerPacket::Message(Message { relay_dock, body }) => {
                            assert_eq!(msg_body, body);
                            assert_eq!(msg_relay_dock, relay_dock);
                            println!("YAY SUCCESS")
                        }
                        InnerPacket::Surbs(_) => todo!(),
                    }
                }
            }
        })
    }

    #[test]
    fn four_relays_forward_pkt() {
        let _ = init_tracing();

        let pkt = InnerPacket::Message(Message {
            relay_dock: 123,
            body: Bytes::from_static(b"lol"),
        });
        smol::block_on(async {
            smol::Timer::after(Duration::from_secs(5)).await;
            let (node1, _node2, _node3, node4) = get_four_connected_relays().await;
            node4
                .send_forward(
                    pkt.clone(),
                    AnonEndpoint::random(),
                    node1
                        .ctx
                        .cfg
                        .relay_config
                        .clone()
                        .unwrap()
                        .0
                        .public()
                        .fingerprint(), // we know node1 is a relay
                )
                .await
                .unwrap();
            match node1.recv().await {
                IncomingMsg::Forward { from: _, body } => {
                    assert_eq!(body, pkt);
                }
                IncomingMsg::Backward { rb_id: _, body: _ } => panic!("not supposed to happen"),
            }
        });
    }

    #[test]
    fn two_relays_one_chat() {
        let _ = init_tracing();

        smol::block_on(async {
            smol::Timer::after(Duration::from_secs(3)).await;
            let (node1, node2) = get_two_connected_relays().await;
            let chat_msg = "hi test".to_string();
            node2
                .send_chat(
                    NeighborId::Relay(
                        node1
                            .ctx
                            .cfg
                            .relay_config
                            .clone()
                            .unwrap()
                            .0
                            .public()
                            .fingerprint(),
                    ), // we know node1 is a relay
                    chat_msg.clone(),
                )
                .await
                .unwrap();

            smol::Timer::after(Duration::from_secs(1)).await;

            let node1_chat_hist = node1
                .get_chat_history(NeighborId::Relay(
                    node2
                        .ctx
                        .cfg
                        .relay_config
                        .clone()
                        .unwrap()
                        .0
                        .public()
                        .fingerprint(),
                ))
                .await
                .unwrap();

            assert_eq!(node1_chat_hist[0].text, chat_msg);
        });
    }
}
