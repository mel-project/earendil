mod gossip;
mod link;
mod link_protocol;
mod link_protocol_impl;
mod link_store;
mod payment_system;
mod route_util;
mod settlement;
mod tests;
mod types;

use link_protocol::LinkClient;
pub use link_store::*;
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

// async fn send_payment(link_node_ctx: &LinkNodeCtx, to: NeighborId) -> anyhow::Result<()> {}

async fn send_msg(
    link_node_ctx: &LinkNodeCtx,
    to: NeighborId,
    msg: LinkMessage,
) -> anyhow::Result<()> {
    let link_w_payinfo = link_node_ctx
        .link_table
        .get(&to)
        .context("no link to this NeighborId")?;
    // check debt & send payment if we are close to the debt limit
    let curr_debt = link_node_ctx.store.get_debt(to).await?;
    tracing::debug!("CURR_DEBT: {curr_debt}");

    if curr_debt as f64 / link_w_payinfo.1.debt_limit as f64 > 0.8 {
        tracing::debug!(
            "almost at debt limit! curr_debt={curr_debt}; debt_limit={}. SENDING PAYMENT!",
            link_w_payinfo.1.debt_limit
        );
        // let task = smolscale::spawn();
        let (paysystem, to_payaddr) = link_node_ctx
            .payment_systems
            .select(&link_w_payinfo.1.paysystem_name_addrs)
            .context("no supported payment system")?;
        let my_id = match link_node_ctx.my_id {
            LinkNodeId::Relay(idsk) => NeighborId::Relay(idsk.public().fingerprint()),
            LinkNodeId::Client(id) => NeighborId::Client(id),
        };
        loop {
            match paysystem.pay(my_id, &to_payaddr, curr_debt as _).await {
                Ok(proof) => {
                    // send payment proof to remote
                    LinkClient(link_w_payinfo.0.rpc_transport())
                        .send_payment_proof(curr_debt as _, paysystem.name(), proof.clone())
                        .await??;
                    // decrement our debt to them
                    link_node_ctx
                        .store
                        .insert_debt_entry(
                            to,
                            DebtEntry {
                                delta: -curr_debt,
                                timestamp: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .expect("time went backwards")
                                    .as_secs(),
                                proof: Some(proof),
                            },
                        )
                        .await?;
                    tracing::debug!("SUCCESSFULLY SENT PAYMENT!");
                    break;
                }
                Err(e) => tracing::warn!("sending payment to {:?} failed with ERR: {e}", to),
            }
        }
    };
    // increment our debt to them
    if link_w_payinfo.1.price > 0 {
        link_node_ctx
            .store
            .insert_debt_entry(
                to,
                DebtEntry {
                    delta: link_w_payinfo.1.price,
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("time went backwards")
                        .as_secs(),
                    proof: None,
                },
            )
            .await?;
    }
    link_w_payinfo.0.send_msg(msg).await?;
    Ok(())
}

// async fn send_payment(link_node_ctx: &LinkNodeCtx, to: NeighborId) -> anyhow::Result<()> {}

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
            let link_node_ctx = link_node_ctx.clone();
            smolscale::spawn(async move {
                if let Some(emit_time) = emit_time {
                    smol::Timer::at(emit_time).await;
                }
                send_msg(
                    &link_node_ctx,
                    NeighborId::Relay(closer_hop),
                    LinkMessage::ToRelay {
                        packet: bytemuck::bytes_of(&pkt).to_vec().into(),
                        next_peeler,
                    },
                )
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
        if let LinkNodeId::Relay(my_idsk) = &link_node_ctx.my_id {
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
                                                let link_node_ctx = link_node_ctx.clone();
                                                smolscale::spawn(async move {
                                                    send_msg(
                                                        &link_node_ctx,
                                                        NeighborId::Client(client_id),
                                                        LinkMessage::ToClient {
                                                            body: pkt.to_vec().into(),
                                                            rb_id,
                                                        },
                                                    )
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
    let (link, their_descr, payment_info, price_config) = match route_config.clone() {
        RouteConfig::Out(config) => {
            let (mux, their_descr, payment_info) =
                pipe_to_mux(&link_node_ctx, pipe, config.price_config.clone()).await?;
            (
                Arc::new(Link::new_dial(mux).await?),
                their_descr,
                payment_info,
                config.price_config,
            )
        }
        RouteConfig::In(config) => {
            let (mux, their_descr, payment_info) =
                pipe_to_mux(&link_node_ctx, pipe, config.price_config.clone()).await?;
            (
                Arc::new(Link::new_listen(mux).await?),
                their_descr,
                payment_info,
                config.price_config,
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

    let pkt_fwd_loop = async {
        // pull messages from the link & forward into LinkNode
        loop {
            let msg = link.recv_msg().await?;
            tracing::trace!("received LinkMessage from {:?}", their_id);
            let debt = link_node_ctx.store.get_debt(their_id).await?;
            if debt > price_config.inbound_debt_limit {
                tracing::warn!(
                    "DROPPING PACKET: {:?} is over their debt limit! debt={debt}; debt_limit={}",
                    their_id,
                    price_config.inbound_debt_limit
                );
                continue;
            };
            // increment remote's debt
            link_node_ctx
                .store
                .insert_debt_entry(
                    their_id,
                    DebtEntry {
                        delta: -price_config.inbound_price,
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("Time went backwards")
                            .as_secs(),
                        proof: None,
                    },
                )
                .await?;
            send_raw.send(msg).await?;
        }
    };

    gossip_loop.race(rpc_serve_loop).race(pkt_fwd_loop).await
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
