mod gossip;
mod link;
mod link_protocol;
mod link_protocol_impl;
mod route_util;
mod settlement;
mod types;

use std::{
    collections::BTreeMap,
    net::{SocketAddr, ToSocketAddrs as _},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
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
use sqlx::{sqlite::SqliteConnectOptions, Pool, Row, Sqlite, SqlitePool};
use stdcode::StdcodeSerializeExt;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::{
    config::{InRouteConfig, ObfsConfig, OutRouteConfig},
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
    pub fn new(cfg: LinkConfig) -> Self {
        let (send_raw, recv_raw) = smol::channel::bounded(1);
        let (send_incoming, recv_incoming) = smol::channel::bounded(1);

        let db = cfg.cache_path.clone().map(|db_path| {
            tracing::debug!("INITIALIZING DATABASE");
            let options = SqliteConnectOptions::from_str(db_path.to_str().unwrap())
                .unwrap()
                .create_if_missing(true);
            smol::future::block_on(async move {
                let pool = Pool::connect_with(options).await.unwrap();
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS misc (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );",
                )
                .execute(&pool)
                .await
                .unwrap();
                pool
            })
        });

        let relay_graph = match smol::future::block_on(db_read(&db, "relay_graph"))
            .ok()
            .flatten()
            .and_then(|s| stdcode::deserialize(&s).ok())
        {
            Some(graph) => graph,
            None => RelayGraph::new(),
        };

        let ctx = LinkNodeCtx {
            cfg,
            my_client_id: rand::random(),
            relay_graph: Arc::new(RwLock::new(relay_graph)),
            my_onion_sk: DhSecret::generate(),
            db,
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

    /// Constructs a reply block back from the given relay.
    pub fn surb_from(
        &self,
        my_anon_id: AnonEndpoint,
        remote: RelayFingerprint, // will use in the future for finding more efficient routes
    ) -> anyhow::Result<(Surb, u64, ReplyDegarbler)> {
        let destination = if let Some(my_relay) = self.ctx.cfg.my_idsk {
            my_relay.public().fingerprint()
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
        let (surb, (id, degarbler)) = Surb::new(
            &reverse_instructs,
            reverse_route[0],
            &dest_opk,
            self.ctx.my_client_id,
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
struct LinkNodeCtx {
    cfg: LinkConfig,
    my_client_id: ClientId,
    my_onion_sk: DhSecret,
    relay_graph: Arc<RwLock<RelayGraph>>,
    db: Option<SqlitePool>,
}

#[tracing::instrument(skip_all)]
async fn link_loop(
    link_ctx: LinkNodeCtx,
    send_raw: Sender<LinkMessage>,
    recv_raw: Receiver<LinkMessage>,
    send_incoming: Sender<IncomingMsg>,
) -> anyhow::Result<()> {
    let table = Arc::new(DashMap::new());

    let db_sync_loop = async {
        loop {
            // println!("syncing DB...");
            let relay_graph = link_ctx.relay_graph.read().stdcode();
            match db_write(&link_ctx.db, "relay_graph", relay_graph).await {
                Ok(_) => (),
                Err(e) => tracing::warn!("db_write failed with: {e}"),
            };
            smol::Timer::after(Duration::from_secs(10)).await;
        }
    };

    let identity_refresh_loop = async {
        if let Some(my_idsk) = link_ctx.cfg.my_idsk {
            loop {
                // println!("WE ARE INSERTING OURSELVES");
                let myself = IdentityDescriptor::new(&my_idsk, &link_ctx.my_onion_sk);
                link_ctx.relay_graph.write().insert_identity(myself)?;
                smol::Timer::after(Duration::from_secs(1)).await;
            }
        } else {
            smol::future::pending().await
        }
    };

    let in_task = async {
        if link_ctx.cfg.in_routes.is_empty() {
            smol::future::pending().await
        } else {
            futures_util::future::try_join_all(link_ctx.cfg.in_routes.iter().map(
                |(name, in_route)| {
                    process_in_route(
                        link_ctx.clone(),
                        name,
                        in_route,
                        table.clone(),
                        send_raw.clone(),
                    )
                },
            ))
            .await
        }
    };

    let out_task = async {
        if link_ctx.cfg.out_routes.is_empty() {
            smol::future::pending().await
        } else {
            futures_util::future::try_join_all(link_ctx.cfg.out_routes.iter().map(
                |(name, out_route)| {
                    process_out_route(
                        link_ctx.clone(),
                        name,
                        out_route,
                        table.clone(),
                        send_raw.clone(),
                    )
                },
            ))
            .await
        }
    };

    let send_to_nonself_next_peeler =
        |emit_time: Option<Instant>, next_peeler: RelayFingerprint, pkt: RawPacket| {
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
            tracing::trace!("sending peeled packet to nonself next_peeler = {next_peeler}");
            let pipe = table
                .get(&NeighborId::Relay(closer_hop))
                .context("cannot find closer hop")?
                .clone();
            // TODO delay queue here rather than this inefficient approach
            smolscale::spawn(async move {
                if let Some(emit_time) = emit_time {
                    smol::Timer::at(emit_time).await;
                }
                pipe.send_msg(LinkMessage::ToRelay {
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
                        tracing::trace!(
                            "{:?} received incoming linkmsg ToRelay. next_peeler = {next_peeler}",
                            link_ctx.cfg.my_idsk.map(|idsk| idsk.public().fingerprint())
                        );
                        let packet: &RawPacket = bytemuck::try_from_bytes(&packet)
                            .ok()
                            .context("could not cast")?;
                        if let Some(my_idsk) = link_ctx.cfg.my_idsk {
                            // I am a relay
                            if next_peeler == my_idsk.public().fingerprint() {
                                // tracing::debug!(
                                //     next_peeler = display(next_peeler),
                                //     "I am the designated peeler"
                                // );
                                let now = Instant::now();
                                let peeled: PeeledPacket = packet.peel(&link_ctx.my_onion_sk)?;
                                tracing::trace!("message peel took {:?}", now.elapsed());
                                match peeled {
                                    PeeledPacket::Relay {
                                        next_peeler,
                                        pkt,
                                        delay_ms,
                                    } => {
                                        // println!(
                                        //     "peeled ToRelay packet. next_peeler = {next_peeler}"
                                        // );
                                        let emit_time =
                                            Instant::now() + Duration::from_millis(delay_ms as u64);
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
                                            "received incoming forward linkmsg from = {from}"
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
                                        if client_id == link_ctx.my_client_id {
                                            tracing::trace!(
                                                rb_id = rb_id,
                                                "received a GARBLED REPLY for myself"
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
                                                "got a GARBLED REPLY to FORWARD to a CLIENT"
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
                            } else {
                                send_to_nonself_next_peeler(None, next_peeler, packet.clone())?
                            }
                        } else {
                            send_to_nonself_next_peeler(None, next_peeler, packet.clone())?
                        }
                    }
                    LinkMessage::ToClient { body, rb_id } => {
                        tracing::trace!(rb_id = rb_id, "received a GARBLED REPLY for myself");
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

    match in_task
        .race(out_task)
        .race(peel_loop)
        .race(db_sync_loop)
        .race(identity_refresh_loop)
        .await
    {
        Ok(_) => tracing::debug!("link_loop() returned?"),
        Err(e) => tracing::error!("link_loop() error: {e}"),
    }
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
        ObfsConfig::None => loop {
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
        ObfsConfig::Sosistab3(_) => todo!(),
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
            if let Err(e) = gossip_once(&link_ctx, &link, their_relay_fp).await {
                tracing::warn!(err = debug(e), "gossip_once failed");
            };
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
                tracing::trace!(
                    "received LinkMessage from {:?} | {their_client_id}",
                    their_relay_fp
                );
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
    pub cache_path: Option<PathBuf>,
}

pub async fn db_write(
    pool: &Option<Pool<Sqlite>>,
    key: &str,
    value: Vec<u8>,
) -> Result<(), sqlx::Error> {
    if let Some(pool) = pool {
        sqlx::query("INSERT INTO misc (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
        .bind(key)
        .bind(value)
        .execute(pool)
        .await?;
    }
    Ok(())
}

pub async fn db_read(
    pool: &Option<Pool<Sqlite>>,
    key: &str,
) -> Result<Option<Vec<u8>>, sqlx::Error> {
    if let Some(pool) = pool {
        let result = sqlx::query("SELECT value FROM misc WHERE key = ?")
            .bind(key)
            .fetch_optional(pool)
            .await?
            .map(|row| row.get("value"));
        Ok(result)
    } else {
        Ok(None)
    }
}

pub fn get_two_connected_relays() -> (LinkNode, LinkNode) {
    let idsk1 = RelayIdentitySecret::generate();
    let mut in_1 = BTreeMap::new();
    in_1.insert(
        "1".to_owned(),
        InRouteConfig {
            listen: "127.0.0.1:30000".parse().unwrap(),
            obfs: ObfsConfig::None,
        },
    );

    let idsk2 = RelayIdentitySecret::generate();
    let mut in_2 = BTreeMap::new();
    in_2.insert(
        "2".to_owned(),
        InRouteConfig {
            listen: "127.0.0.1:30001".parse().unwrap(),
            obfs: ObfsConfig::None,
        },
    );
    let mut out_2 = BTreeMap::new();
    out_2.insert(
        "1".to_owned(),
        OutRouteConfig {
            connect: "127.0.0.1:30000".parse().unwrap(),
            fingerprint: idsk1.public().fingerprint(),
            obfs: ObfsConfig::None,
        },
    );

    let node1 = LinkNode::new(LinkConfig {
        in_routes: in_1,
        out_routes: BTreeMap::new(),
        my_idsk: Some(idsk1),
        cache_path: None,
    });

    let node2 = LinkNode::new(LinkConfig {
        in_routes: in_2,
        out_routes: out_2,
        my_idsk: Some(idsk2),
        cache_path: None,
    });

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

pub fn get_connected_relay_client() -> (LinkNode, LinkNode) {
    let idsk1 = RelayIdentitySecret::generate();
    let mut in_1 = BTreeMap::new();
    in_1.insert(
        "1".to_owned(),
        InRouteConfig {
            listen: "127.0.0.1:30000".parse().unwrap(),
            obfs: ObfsConfig::None,
        },
    );

    let mut in_2 = BTreeMap::new();
    in_2.insert(
        "2".to_owned(),
        InRouteConfig {
            listen: "127.0.0.1:30001".parse().unwrap(),
            obfs: ObfsConfig::None,
        },
    );
    let mut out_2 = BTreeMap::new();
    out_2.insert(
        "1".to_owned(),
        OutRouteConfig {
            connect: "127.0.0.1:30000".parse().unwrap(),
            fingerprint: idsk1.public().fingerprint(),
            obfs: ObfsConfig::None,
        },
    );

    let node1 = LinkNode::new(LinkConfig {
        in_routes: in_1,
        out_routes: BTreeMap::new(),
        my_idsk: Some(idsk1),
        cache_path: None,
    });

    let node2 = LinkNode::new(LinkConfig {
        in_routes: in_2,
        out_routes: out_2,
        my_idsk: None,
        cache_path: None,
    });

    (node1, node2)
}

pub fn get_four_connected_relays() -> (LinkNode, LinkNode, LinkNode, LinkNode) {
    let idsk1 = RelayIdentitySecret::generate();
    let mut in_1 = BTreeMap::new();
    in_1.insert(
        "1".to_owned(),
        InRouteConfig {
            listen: "127.0.0.1:30000".parse().unwrap(),
            obfs: ObfsConfig::None,
        },
    );

    let idsk2 = RelayIdentitySecret::generate();
    let mut in_2 = BTreeMap::new();
    in_2.insert(
        "2".to_owned(),
        InRouteConfig {
            listen: "127.0.0.1:30001".parse().unwrap(),
            obfs: ObfsConfig::None,
        },
    );
    let mut out_2 = BTreeMap::new();
    out_2.insert(
        "1".to_owned(),
        OutRouteConfig {
            connect: "127.0.0.1:30000".parse().unwrap(),
            fingerprint: idsk1.public().fingerprint(),
            obfs: ObfsConfig::None,
        },
    );

    let idsk3 = RelayIdentitySecret::generate();
    let mut in_3 = BTreeMap::new();
    in_3.insert(
        "1".to_owned(),
        InRouteConfig {
            listen: "127.0.0.1:30002".parse().unwrap(),
            obfs: ObfsConfig::None,
        },
    );
    let mut out_3 = BTreeMap::new();
    out_3.insert(
        "1".to_owned(),
        OutRouteConfig {
            connect: "127.0.0.1:30001".parse().unwrap(),
            fingerprint: idsk1.public().fingerprint(),
            obfs: ObfsConfig::None,
        },
    );
    let idsk4 = RelayIdentitySecret::generate();
    let mut in_4 = BTreeMap::new();
    in_4.insert(
        "2".to_owned(),
        InRouteConfig {
            listen: "127.0.0.1:30003".parse().unwrap(),
            obfs: ObfsConfig::None,
        },
    );
    let mut out_4 = BTreeMap::new();
    out_4.insert(
        "1".to_owned(),
        OutRouteConfig {
            connect: "127.0.0.1:30002".parse().unwrap(),
            fingerprint: idsk1.public().fingerprint(),
            obfs: ObfsConfig::None,
        },
    );

    let node1 = LinkNode::new(LinkConfig {
        in_routes: in_1,
        out_routes: BTreeMap::new(),
        my_idsk: Some(idsk1),
        cache_path: None,
    });
    let node2 = LinkNode::new(LinkConfig {
        in_routes: in_2,
        out_routes: out_2,
        my_idsk: Some(idsk2),
        cache_path: None,
    });
    let node3 = LinkNode::new(LinkConfig {
        in_routes: in_3,
        out_routes: out_3,
        my_idsk: Some(idsk3),
        cache_path: None,
    });
    let node4 = LinkNode::new(LinkConfig {
        in_routes: in_4,
        out_routes: out_4,
        my_idsk: Some(idsk4),
        cache_path: None,
    });

    (node1, node2, node3, node4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use earendil_packet::RawBody;

    #[test]
    fn two_relays_one_forward_pkt() {
        init_tracing().unwrap();

        let (node1, node2) = get_two_connected_relays();
        let pkt = InnerPacket::Message(Message {
            relay_dock: 123,
            body: Bytes::from_static(b"lol"),
        });
        smol::block_on(async {
            smol::Timer::after(Duration::from_secs(3)).await;
            node2
                .send_forward(
                    pkt.clone(),
                    AnonEndpoint::random(),
                    node1.ctx.cfg.my_idsk.unwrap().public().fingerprint(), // we know node1 is a relay
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
        init_tracing().unwrap();

        let (node1, node2) = get_two_connected_relays();
        println!(
            "node1 fp = {}",
            node1.ctx.cfg.my_idsk.unwrap().public().fingerprint()
        );
        println!(
            "node2 fp = {}",
            node2.ctx.cfg.my_idsk.unwrap().public().fingerprint()
        );
        smol::block_on(async {
            smol::Timer::after(Duration::from_secs(3)).await;
            let (surb_1to2, surb_id, degarbler) = node2
                .surb_from(
                    AnonEndpoint::random(),
                    node1.ctx.cfg.my_idsk.unwrap().public().fingerprint(),
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
        init_tracing().unwrap();

        let (relay_node, client_node) = get_connected_relay_client();
        let pkt = InnerPacket::Message(Message {
            relay_dock: 123,
            body: Bytes::from_static(b"lol"),
        });
        smol::block_on(async {
            smol::Timer::after(Duration::from_secs(3)).await;
            client_node
                .send_forward(
                    pkt.clone(),
                    AnonEndpoint::random(),
                    relay_node.ctx.cfg.my_idsk.unwrap().public().fingerprint(), // we know node1 is a relay
                )
                .await
                .unwrap();
            println!("client --> relay LinkMsg sent");
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
        init_tracing().unwrap();

        let (relay_node, client_node) = get_connected_relay_client();
        println!(
            "node1 fp = {}",
            relay_node.ctx.cfg.my_idsk.unwrap().public().fingerprint()
        );
        smol::block_on(async {
            smol::Timer::after(Duration::from_secs(3)).await;
            let (surb_1to2, surb_id, degarbler) = client_node
                .surb_from(
                    AnonEndpoint::random(),
                    relay_node.ctx.cfg.my_idsk.unwrap().public().fingerprint(),
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
        init_tracing().unwrap();

        let (node1, node2, node3, node4) = get_four_connected_relays();
        let pkt = InnerPacket::Message(Message {
            relay_dock: 123,
            body: Bytes::from_static(b"lol"),
        });
        smol::block_on(async {
            smol::Timer::after(Duration::from_secs(5)).await;
            node4
                .send_forward(
                    pkt.clone(),
                    AnonEndpoint::random(),
                    node1.ctx.cfg.my_idsk.unwrap().public().fingerprint(), // we know node1 is a relay
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
}
