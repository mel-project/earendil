use std::{
    ops::Deref,
    time::{Duration, Instant},
};

use blake3::Hash;
use bytes::Bytes;
use dashmap::{DashMap, DashSet};
use earendil_crypt::{AnonDest, ClientId, RelayFingerprint, RelayIdentitySecret, SourceId};
use earendil_packet::{
    crypt::OnionSecret, Dock, InnerPacket, Message, RawBody, RawPacket, ReplyBlock, ReplyDegarbler,
};
use earendil_topology::RelayGraph;

use moka::sync::{Cache, CacheBuilder};
use parking_lot::{Mutex, RwLock};
use rand::seq::SliceRandom;
use smol::{channel::Sender, Timer};

use crate::{
    bicache::Bicache,
    config::ConfigFile,
    control_protocol::SendMessageError,
    daemon::route_to_instructs,
    socket::{AnonEndpoint, RelayEndpoint},
};

use super::{
    db::db_read, debts::Debts, delay_queue::DelayQueue, reply_block_store::ReplyBlockStore,
    rrb_balance::replenish_rrb, settlement::Settlements,
};

pub type DaemonContext = anyctx::AnyCtx<ConfigFile>;
pub type CtxField<T> = fn(&DaemonContext) -> T;

pub static GLOBAL_IDENTITY: CtxField<Option<RelayIdentitySecret>> = |ctx| {
    if ctx.init().in_routes.is_empty() {
        None
    } else {
        Some(
            ctx.init()
                .identity
                .as_ref()
                .map(|id| {
                    id.actualize_relay()
                        .expect("failed to initialize global identity")
                })
                .unwrap_or_else(|| {
                    let ctx = ctx.clone();
                    smol::future::block_on(async move {
                        match db_read(&ctx, "global_identity").await {
                            Ok(Some(id)) => {
                                if let Ok(id_bytes) = &id.try_into() {
                                    RelayIdentitySecret::from_bytes(id_bytes)
                                } else {
                                    RelayIdentitySecret::generate()
                                }
                            }
                            _ => RelayIdentitySecret::generate(),
                        }
                    })
                }),
        )
    }
};

pub static GLOBAL_ONION_SK: CtxField<OnionSecret> = |_| OnionSecret::generate();
pub static RELAY_GRAPH: CtxField<RwLock<RelayGraph>> = |ctx| {
    let ctx = ctx.clone();
    smol::future::block_on(async move {
        match db_read(&ctx, "relay_graph")
            .await
            .ok()
            .flatten()
            .and_then(|s| stdcode::deserialize(&s).ok())
        {
            Some(g) => RwLock::new(g),
            None => {
                tracing::debug!("**** INIT RELAY GRAPH****");
                RwLock::new(RelayGraph::new())
            }
        }
    })
};
pub static ANON_DESTS: CtxField<Mutex<ReplyBlockStore>> = |_| Mutex::new(ReplyBlockStore::new());

pub static NEIGH_TABLE_NEW: CtxField<
    Cache<RelayFingerprint, Sender<(RawPacket, RelayFingerprint)>>,
> = |_| {
    CacheBuilder::default()
        .time_to_live(Duration::from_secs(120))
        .build()
}; // TODO a better solution for deletion

pub static CLIENT_TABLE: CtxField<Cache<ClientId, Sender<(RawBody, u64)>>> = |_| {
    CacheBuilder::default()
        .time_to_live(Duration::from_secs(120))
        .build()
};

pub static CLIENT_IDENTITIES: CtxField<Bicache<RelayFingerprint, ClientId>> = |_| Bicache::new(120);
pub static ANON_IDENTITIES: CtxField<Cache<RelayFingerprint, AnonDest>> = |_| {
    CacheBuilder::default()
        .time_to_live(Duration::from_secs(120))
        .build()
};

pub static CLIENT_SOCKET_RECV_QUEUES: CtxField<DashMap<AnonEndpoint, Sender<(Message, SourceId)>>> =
    |_| Default::default();
pub static RELAY_SOCKET_RECV_QUEUES: CtxField<DashMap<RelayEndpoint, Sender<(Message, SourceId)>>> =
    |_| Default::default();
pub static DEGARBLERS: CtxField<DashMap<u64, ReplyDegarbler>> = |_| Default::default();

pub static DEBTS: CtxField<Debts> = |ctx| {
    let ctx = ctx.clone();
    smol::future::block_on(async move {
        match db_read(&ctx, "debts").await {
            Ok(Some(debts)) => {
                tracing::debug!("retrieving persisted debts");
                match Debts::from_bytes(debts) {
                    Ok(debts) => debts,
                    Err(e) => {
                        tracing::warn!("debt decode error: {e}");
                        Debts::new()
                    }
                }
            }
            _ => {
                tracing::debug!("initializing debts");
                Debts::new()
            }
        }
    })
};

pub static SETTLEMENTS: CtxField<Settlements> = |ctx| Settlements::new(ctx.init().auto_settle);

pub static DELAY_QUEUE: CtxField<DelayQueue<(RawPacket, RelayFingerprint)>> = |_| DelayQueue::new();

pub static PKTS_SEEN: CtxField<DashSet<Hash>> = |_| DashSet::new();

/// Sends a message with a replyblock with the given parameters.
#[tracing::instrument(skip(ctx, content))]
pub async fn send_reply(
    ctx: &DaemonContext,
    src_dock: Dock,
    anon_dest: AnonDest,
    dst_dock: Dock,
    content: Vec<Bytes>,
) -> Result<(), SendMessageError> {
    tracing::debug!("calling send_reply here");
    let now = Instant::now();
    let _guard = scopeguard::guard((), |_| {
        let send_msg_time = now.elapsed();
        tracing::trace!("send message took {:?}", send_msg_time);
    });

    let maybe_reply_block = ctx.get(ANON_DESTS).lock().pop(&anon_dest);
    let fallible = || -> Result<(), SendMessageError> {
        if let Some(reply_block) = maybe_reply_block.clone() {
            let inner = InnerPacket::Message(Message::new(src_dock, dst_dock, content.clone()));
            let raw_packet = RawPacket::new_reply(
                &reply_block,
                inner,
                &SourceId::Relay(
                    ctx.get(GLOBAL_IDENTITY)
                        .expect("only relays have global identities")
                        .public()
                        .fingerprint(),
                ),
            )?;
            let emit_time = Instant::now();
            ctx.get(DELAY_QUEUE)
                .insert((raw_packet, reply_block.first_peeler), emit_time);
        } else {
            return Err(SendMessageError::ReplyBlockFailed);
        };

        Ok(())
    };

    match fallible() {
        Ok(()) => (),
        Err(e) => {
            tracing::warn!(
                "error sending packet with no reply blocks; retrying in one second: {e}"
            );

            Timer::after(Duration::from_secs(1)).await;
            fallible()?;
        }
    }

    Ok(())
}

/// Sends a raw N2R message with the given parameters.
#[tracing::instrument(skip(ctx, content))]
pub async fn send_n2r(
    ctx: &DaemonContext,
    src: AnonDest,
    src_dock: Dock,
    dst_fp: RelayFingerprint,
    dst_dock: Dock,
    content: Vec<Bytes>,
) -> Result<(), SendMessageError> {
    tracing::debug!("calling send_n2r here");
    let now = Instant::now();
    let _guard = scopeguard::guard((), |_| {
        let send_msg_time = now.elapsed();
        tracing::trace!("send message took {:?}", send_msg_time);
    });

    let route = match forward_route(ctx) {
        Some(r) => r,
        None => return Err(SendMessageError::NoRoute(dst_fp)),
    };
    let first_peeler = route[0];

    let instructs = {
        let graph = ctx.get(RELAY_GRAPH).read();
        route_to_instructs(route.clone(), &graph)
    }?;
    tracing::trace!(
        "*************************** translated this route to instructions: {:?}",
        route
    );
    let dest_opk = ctx
        .get(RELAY_GRAPH)
        .read()
        .identity(&dst_fp)
        .ok_or(SendMessageError::NoOnionPublic(dst_fp))?
        .onion_pk;
    let wrapped_onion = RawPacket::new_normal(
        &instructs,
        &dest_opk,
        InnerPacket::Message(Message::new(src_dock, dst_dock, content.clone())),
        SourceId::Anon(src),
    )?;

    replenish_rrb(ctx, src, dst_fp)?;

    let emit_time = Instant::now();
    ctx.get(DELAY_QUEUE)
        .insert((wrapped_onion, first_peeler), emit_time);

    Ok(())
}

fn forward_route(ctx: &DaemonContext) -> Option<Vec<RelayFingerprint>> {
    let route = ctx.get(RELAY_GRAPH).read().rand_relays(3);
    tracing::debug!("forward route formed: {:?}", route);
    Some(route)
}

fn reply_route(ctx: &DaemonContext) -> Option<Vec<RelayFingerprint>> {
    let mut route = ctx.get(RELAY_GRAPH).read().rand_relays(3);
    let my_neighs: Vec<RelayFingerprint> =
        ctx.get(NEIGH_TABLE_NEW).iter().map(|(fp, _)| *fp).collect();
    let rand_neigh = my_neighs.choose(&mut rand::thread_rng()).copied();

    match rand_neigh {
        Some(neigh) => route.push(neigh),
        None => return None,
    }

    tracing::debug!("reply route formed: {:?}", route);
    Some(route)
}

#[tracing::instrument(skip(ctx))]
/// Send a batch of reply blocks to the given N2R destination.
pub async fn send_reply_blocks(
    ctx: &DaemonContext,
    count: usize,
    my_anon_id: AnonDest,
    dst_fp: RelayFingerprint,
) -> Result<(), SendMessageError> {
    tracing::trace!("sending a batch of {count} reply blocks to {dst_fp}");

    let route = match forward_route(ctx) {
        Some(r) => r,
        None => return Err(SendMessageError::NoRoute(dst_fp)),
    };
    let first_peeler = route[0];

    let dest_opk = ctx
        .get(RELAY_GRAPH)
        .read()
        .identity(&dst_fp)
        .ok_or(SendMessageError::NoOnionPublic(dst_fp))?
        .onion_pk;

    let instructs = route_to_instructs(route.clone(), ctx.get(RELAY_GRAPH).read().deref())?;
    // currently the path for every one of them is the same; will want to change this in the future
    let reverse_route = match reply_route(ctx) {
        Some(r) => r,
        None => return Err(SendMessageError::NoRoute(dst_fp)),
    };

    let reverse_instructs = route_to_instructs(reverse_route, ctx.get(RELAY_GRAPH).read().deref())?;

    let mut rbs: Vec<ReplyBlock> = vec![];
    for _ in 0..count {
        let (rb, (id, degarbler)) =
            ReplyBlock::new(&reverse_instructs, first_peeler, &dest_opk, my_anon_id)
                .map_err(|_| SendMessageError::ReplyBlockFailed)?;
        rbs.push(rb);
        ctx.get(DEGARBLERS).insert(id, degarbler);
    }
    let wrapped_rb_onion = RawPacket::new_normal(
        &instructs,
        &dest_opk,
        InnerPacket::ReplyBlocks(rbs),
        SourceId::Anon(my_anon_id),
    )?;

    let emit_time = Instant::now();
    ctx.get(DELAY_QUEUE)
        .insert((wrapped_rb_onion, first_peeler), emit_time);

    Ok(())
}
