mod gossip;
mod link;
mod link_protocol;
mod link_protocol_impl;
mod route_util;
mod types;

use std::{
    collections::BTreeMap,
    net::{SocketAddr, ToSocketAddrs as _},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context as _;
use bytes::Bytes;
use clone_macro::clone;
use dashmap::DashMap;
use earendil_crypt::{AnonEndpoint, RelayFingerprint, RelayIdentitySecret, RemoteId};
use earendil_packet::{crypt::DhSecret, InnerPacket, Message, PeeledPacket, RawPacket, ReplyBlock};
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
use stdcode::StdcodeSerializeExt as _;

use crate::{
    link_node::route_util::{forward_route_to, one_hop_closer, route_to_instructs},
    pascal::{read_pascal, write_pascal},
    InRouteConfig, ObfsConfig, OutRouteConfig,
};

use self::{
    gossip::gossip_once,
    link::{Link, LinkMessage},
    link_protocol::LinkService,
    link_protocol_impl::LinkProtocolImpl,
    types::{ClientId, NeighborId},
};

/// An implementation of the link-level interface.
pub struct LinkNode {
    ctx: LinkNodeCtx,
    _task: Immortal,
    send_raw: Sender<LinkMessage>,
    recv_incoming: Receiver<IncomingMsg>,
}

impl LinkNode {
    /// Creates a new link node.
    pub fn new(cfg: LinkConfig) -> Self {
        let (send_raw, recv_raw) = smol::channel::bounded(1);
        let (send_incoming, recv_incoming) = smol::channel::bounded(1);
        let ctx = LinkNodeCtx {
            cfg,
            my_client_id: rand::random(),
            relay_graph: Arc::new(RwLock::new(RelayGraph::new())),
            my_onion_sk: DhSecret::generate(),
        };
        let _task = Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([ctx, send_raw, recv_raw], move || link_loop(
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
            let first_peeler = *route
                .first()
                .context("empty route, cannot obtain first peeler")?;

            let instructs =
                route_to_instructs(&relay_graph, &route).context("route_to_instructs failed")?;
            tracing::trace!(
                "translated this route to instructions: {:?} => {:?}",
                route,
                instructs
            );

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
    pub async fn send_backwards(
        &self,
        reply_block: ReplyBlock,
        message: Message,
    ) -> anyhow::Result<()> {
        let packet = RawPacket::new_reply(
            &reply_block,
            InnerPacket::Message(message.clone()),
            &RemoteId::Relay(
                self.ctx
                    .cfg
                    .my_idsk
                    .context("we must be a relay to send backwards packets")?
                    .public()
                    .fingerprint(),
            ),
        )?;
        self.send_raw(packet, reply_block.first_peeler).await;
        Ok(())
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

    /// Obtains the current LinkNode's client ID, for creating raw packets.
    fn client_id(&self) -> ClientId {
        self.ctx.my_client_id
    }

    /// Receives an incoming message. Blocks until we have something that's for us, and not to be forwarded elsewhere.
    pub async fn recv(&self) -> IncomingMsg {
        self.recv_incoming.recv().await.unwrap()
    }
}

/// Incoming messages from the link layer that are addressed to "us".
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
struct LinkNodeCtx {
    cfg: LinkConfig,
    my_client_id: ClientId,
    my_onion_sk: DhSecret,
    relay_graph: Arc<RwLock<RelayGraph>>,
}

async fn link_loop(
    link_ctx: LinkNodeCtx,
    send_raw: Sender<LinkMessage>,
    recv_raw: Receiver<LinkMessage>,
    send_incoming: Sender<IncomingMsg>,
) -> anyhow::Result<()> {
    let table = Arc::new(DashMap::new());
    let in_tasks = link_ctx.cfg.in_routes.iter().map(|(name, in_route)| {
        process_in_route(
            link_ctx.clone(),
            name,
            in_route,
            table.clone(),
            send_raw.clone(),
        )
    });
    let out_tasks = link_ctx.cfg.out_routes.iter().map(|(name, out_route)| {
        process_out_route(
            link_ctx.clone(),
            name,
            out_route,
            table.clone(),
            send_raw.clone(),
        )
    });

    // the main peel loop
    let peel_loop = async {
        loop {
            let incoming = recv_raw.recv().await?;
            let fallible = async {
                match incoming {
                    LinkMessage::ToRelay {
                        packet,
                        next_peeler,
                    } => {
                        let packet: &RawPacket = bytemuck::try_from_bytes(&packet)
                            .ok()
                            .context("could not cast")?;
                        if let Some(my_idsk) = link_ctx.cfg.my_idsk {
                            if next_peeler == my_idsk.public().fingerprint() {
                                tracing::debug!(
                                    next_peeler = display(next_peeler),
                                    "I am the designated peeler"
                                );
                                let now = Instant::now();
                                let peeled: PeeledPacket = packet.peel(&link_ctx.my_onion_sk)?;
                                tracing::debug!("message peel took {:?}", now.elapsed());
                                match peeled {
                                    PeeledPacket::Relay {
                                        next_peeler,
                                        pkt,
                                        delay_ms,
                                    } => {
                                        let emit_time =
                                            Instant::now() + Duration::from_millis(delay_ms as u64);
                                        let closer_hop = {
                                            let graph = link_ctx.relay_graph.read();
                                            let my_neighs = table
                                                .iter()
                                                .map(|p| *p.key())
                                                .filter_map(|p| match p {
                                                    NeighborId::Relay(r) => Some(r),
                                                    NeighborId::Client(_) => None,
                                                })
                                                .collect_vec();
                                            one_hop_closer(&my_neighs, &graph, next_peeler)?
                                        };
                                        let pipe = table
                                            .get(&NeighborId::Relay(closer_hop))
                                            .context("cannot find closer hop")?
                                            .clone();
                                        // TODO delay queue here rather than this inefficient approach
                                        smolscale::spawn(async move {
                                            smol::Timer::at(emit_time).await;
                                            pipe.send_msg(LinkMessage::ToRelay {
                                                packet: bytemuck::bytes_of(&pkt).to_vec().into(),
                                                next_peeler,
                                            })
                                            .await?;
                                            anyhow::Ok(())
                                        })
                                        .detach();
                                    }
                                    PeeledPacket::Received { from, pkt } => {
                                        send_incoming
                                            .send(IncomingMsg::Forward { from, body: pkt })
                                            .await?;
                                    }
                                    PeeledPacket::GarbledReply {
                                        rb_id,
                                        pkt,
                                        client_id,
                                    } => {
                                        if client_id == link_ctx.my_client_id {
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
                                                "got a GARBLED REPLY to FORWARD to the CLIENT!!!"
                                            );
                                            let table = table.clone();
                                            smolscale::spawn(async move {
                                                table
                                                    .get(&NeighborId::Client(client_id))
                                                    .context("no such client")?
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
                tracing::error!(err = debug(err), "error in peel loop");
            }
        }
    };

    futures_util::future::try_join_all(in_tasks)
        .race(futures_util::future::try_join_all(out_tasks))
        .race(peel_loop)
        .await?;
    Ok(())
}

async fn process_in_route(
    link_ctx: LinkNodeCtx,
    name: &str,
    in_route: &InRouteConfig,
    table: Arc<DashMap<NeighborId, Link>>,
    send_raw: Sender<LinkMessage>,
) -> anyhow::Result<()> {
    let mut listener = TcpListener::bind(in_route.listen).await?;
    match &in_route.obfs {
        crate::ObfsConfig::None => loop {
            let pipe = listener.accept().await?;
            tracing::debug!(
                name,
                remote_addr = debug(pipe.remote_addr()),
                "accepted a TCP connection"
            );
            smolscale::spawn(handle_pipe(
                link_ctx.clone(),
                pipe,
                table.clone(),
                send_raw.clone(),
                false,
            ))
            .detach();
        },
        crate::ObfsConfig::Sosistab3(_) => todo!(),
    }
}

async fn process_out_route(
    link_ctx: LinkNodeCtx,
    name: &str,
    out_route: &OutRouteConfig,
    table: Arc<DashMap<NeighborId, Link>>,
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
                        link_ctx.clone(),
                        tcp_pipe,
                        table.clone(),
                        send_raw.clone(),
                        true,
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

async fn handle_pipe(
    link_ctx: LinkNodeCtx,
    pipe: impl Pipe,
    table: Arc<DashMap<NeighborId, Link>>,
    send_raw: Sender<LinkMessage>,
    is_dial: bool,
) -> anyhow::Result<()> {
    let (mux, their_client_id, their_id_desc) = pipe_to_mux(&link_ctx, pipe).await?;
    let link = if is_dial {
        Link::new_dial(mux).await?
    } else {
        Link::new_listen(mux).await?
    };

    // insert *both* as client and as relay
    if let Some(their_id_desc) = &their_id_desc {
        their_id_desc.verify()?;
        table.insert(
            NeighborId::Relay(their_id_desc.identity_pk.fingerprint()),
            link.clone(),
        );
    }
    table.insert(NeighborId::Client(their_client_id), link.clone());

    let their_relay_fp = their_id_desc
        .as_ref()
        .map(|desc| desc.identity_pk.fingerprint());

    let gossip_loop = async {
        loop {
            smol::Timer::after(Duration::from_secs(1)).await;
            gossip_once(&link_ctx, &link, their_relay_fp).await?;
        }
    };

    let rpc_serve_loop = link.rpc_serve(LinkService(LinkProtocolImpl {
        ctx: link_ctx.clone(),
        remote_client_id: their_client_id,
        remote_relay_fp: their_relay_fp,
    }));

    // pull messages from the link
    gossip_loop
        .race(rpc_serve_loop)
        .race(async {
            loop {
                let msg = link.recv_msg().await?;
                send_raw.send(msg).await?;
            }
        })
        .await
}

async fn pipe_to_mux(
    link_ctx: &LinkNodeCtx,
    pipe: impl Pipe,
) -> anyhow::Result<(PicoMux, ClientId, Option<IdentityDescriptor>)> {
    let (mut read, mut write) = pipe.split();

    let send_auth = async {
        let my_relay_descr = link_ctx
            .cfg
            .my_idsk
            .map(|id| IdentityDescriptor::new(&id, &link_ctx.my_onion_sk));
        let auth_msg = (link_ctx.my_client_id, my_relay_descr).stdcode();
        write_pascal(&auth_msg, &mut write).await?;
        anyhow::Ok(())
    };

    let recv_auth = async {
        let bts = read_pascal(&mut read).await?;
        let (their_client_id, their_relay_descr): (ClientId, Option<IdentityDescriptor>) =
            stdcode::deserialize(&bts)?;
        anyhow::Ok((their_client_id, their_relay_descr))
    };

    let (a, b) = futures::join!(send_auth, recv_auth);
    a?;
    let (their_client_id, their_relay_descr) = b?;
    let mux = PicoMux::new(read, write);
    Ok((mux, their_client_id, their_relay_descr))
}

#[derive(Clone, Debug)]
pub struct LinkConfig {
    pub in_routes: BTreeMap<String, InRouteConfig>,
    pub out_routes: BTreeMap<String, OutRouteConfig>,
    pub my_idsk: Option<RelayIdentitySecret>,
}
