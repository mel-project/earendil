use std::{
    ops::Deref,
    time::{Duration, Instant},
};

use blake3::Hash;
use bytes::Bytes;
use dashmap::{DashMap, DashSet};
use earendil_crypt::{Fingerprint, IdentitySecret};
use earendil_packet::{
    crypt::{OnionPublic, OnionSecret},
    Dock, InnerPacket, Message, RawPacket, ReplyBlock, ReplyDegarbler,
};
use earendil_topology::RelayGraph;

use itertools::Itertools;
use moka::sync::{Cache, CacheBuilder};
use once_cell::sync::Lazy;
use parking_lot::{Mutex, RwLock};
use rand::seq::SliceRandom;
use smol::{channel::Sender, Timer};

use crate::{
    config::ConfigFile, control_protocol::SendMessageError, daemon::route_to_instructs,
    socket::Endpoint,
};

use super::{
    db::db_read, debts::Debts, delay_queue::DelayQueue, reply_block_store::ReplyBlockStore,
    rrb_balance::replenish_rrb, settlement::Settlements,
};

pub type DaemonContext = anyctx::AnyCtx<ConfigFile>;
pub type CtxField<T> = fn(&DaemonContext) -> T;

pub static GLOBAL_IDENTITY: CtxField<IdentitySecret> = |ctx| {
    ctx.init()
        .identity
        .as_ref()
        .map(|id| {
            id.actualize()
                .expect("failed to initialize global identity")
        })
        .unwrap_or_else(|| {
            let ctx = ctx.clone();
            smol::future::block_on(async move {
                match db_read(&ctx, "global_identity").await {
                    Ok(Some(id)) => {
                        if let Ok(id_bytes) = &id.try_into() {
                            IdentitySecret::from_bytes(id_bytes)
                        } else {
                            IdentitySecret::generate()
                        }
                    }
                    _ => IdentitySecret::generate(),
                }
            })
        })
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

pub static NEIGH_TABLE_NEW: CtxField<Cache<Fingerprint, Sender<(RawPacket, Fingerprint)>>> = |_| {
    CacheBuilder::default()
        .time_to_live(Duration::from_secs(120))
        .build()
}; // TODO a better solution for deletion
pub static SOCKET_RECV_QUEUES: CtxField<DashMap<Endpoint, Sender<(Message, Fingerprint)>>> =
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

type NextPeeler = Fingerprint;
pub static DELAY_QUEUE: CtxField<DelayQueue<(RawPacket, NextPeeler)>> = |_| DelayQueue::new();

pub static PKTS_SEEN: CtxField<DashSet<Hash>> = |_| DashSet::new();

/// Sends a raw N2R message with the given parameters.
#[tracing::instrument(skip(ctx, content))]
pub async fn send_n2r(
    ctx: &DaemonContext,
    src_idsk: IdentitySecret,
    src_dock: Dock,
    dst_fp: Fingerprint,
    dst_dock: Dock,
    content: Vec<Bytes>,
) -> Result<(), SendMessageError> {
    tracing::debug!("calling send_n2r here");
    let now = Instant::now();
    let _guard = scopeguard::guard((), |_| {
        let send_msg_time = now.elapsed();
        tracing::trace!("send message took {:?}", send_msg_time);
    });

    let my_sk = ctx.get(GLOBAL_IDENTITY);
    let src_anon = &src_idsk != my_sk;

    let maybe_reply_block = ctx.get(ANON_DESTS).lock().pop(&dst_fp);
    if let Some(reply_block) = maybe_reply_block {
        if src_anon {
            return Err(SendMessageError::NoAnonId);
        }
        let inner = InnerPacket::Message(Message::new(src_dock, dst_dock, content));
        let raw_packet = RawPacket::new_reply(&reply_block, inner, &src_idsk)?;
        let emit_time = Instant::now();
        ctx.get(DELAY_QUEUE)
            .insert((raw_packet, reply_block.first_peeler), emit_time);
    } else {
        let fallible = || -> Result<(), SendMessageError> {
            let route = match forward_route(ctx, dst_fp) {
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
            let dest_is_relay = if let Some(id) = ctx.get(RELAY_GRAPH).read().identity(&dst_fp) {
                id.is_relay
            } else {
                false
            };
            let wrapped_onion = RawPacket::new_normal(
                &instructs,
                &dest_opk,
                dest_is_relay,
                InnerPacket::Message(Message::new(src_dock, dst_dock, content.clone())),
                &src_idsk,
            )?;

            // if anon source, send RBs
            if src_anon {
                replenish_rrb(ctx, src_idsk, dst_fp)?;
            }

            let emit_time = Instant::now();
            ctx.get(DELAY_QUEUE)
                .insert((wrapped_onion, first_peeler), emit_time);

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
    }
    Ok(())
}

fn forward_route(ctx: &DaemonContext, dst_fp: Fingerprint) -> Option<Vec<Fingerprint>> {
    let mut route = ctx.get(RELAY_GRAPH).read().rand_relays(3);
    // if the destination is a client, then the penultimate must be a random neighbor of it
    let is_relay = if let Some(id) = ctx.get(RELAY_GRAPH).read().identity(&dst_fp) {
        id.is_relay
    } else {
        false
    };
    if !is_relay {
        match random_neigh_of(ctx, dst_fp) {
            Some(neigh) => {
                route.pop();
                route.push(neigh);
            }
            None => return None,
        }
    }
    route.push(dst_fp);
    tracing::debug!("forward route formed: {:?}", route);
    Some(route)
}

fn reply_route(ctx: &DaemonContext) -> Option<Vec<Fingerprint>> {
    let my_fp = ctx.get(GLOBAL_IDENTITY).public().fingerprint();
    let mut route = ctx.get(RELAY_GRAPH).read().rand_relays(3);
    match random_neigh_of(ctx, my_fp) {
        Some(neigh) => route.push(neigh),
        None => return None,
    }
    route.push(ctx.get(GLOBAL_IDENTITY).public().fingerprint());
    tracing::debug!("reply route formed: {:?}", route);
    Some(route)
}

fn random_neigh_of(ctx: &DaemonContext, fp: Fingerprint) -> Option<Fingerprint> {
    let my_neighs = ctx
        .get(RELAY_GRAPH)
        .read()
        .neighbors(&fp)
        .map(|s| s.collect_vec())
        .unwrap_or_default();
    my_neighs.choose(&mut rand::thread_rng()).copied()
}

#[tracing::instrument(skip(ctx))]
/// Send a batch of reply blocks to the given N2R destination.
pub async fn send_reply_blocks(
    ctx: &DaemonContext,
    count: usize,
    my_anon_isk: IdentitySecret,
    dst_fp: Fingerprint,
) -> Result<(), SendMessageError> {
    static ONION_SK_CACHE: Lazy<Cache<Fingerprint, OnionSecret>> = Lazy::new(|| Cache::new(100000));
    let my_anon_osk = ONION_SK_CACHE.get_with(my_anon_isk.public().fingerprint(), || {
        OnionSecret::generate()
    });

    tracing::trace!("sending a batch of {count} reply blocks to {dst_fp}");

    let route = match forward_route(ctx, dst_fp) {
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
    let dest_is_relay = if let Some(id) = ctx.get(RELAY_GRAPH).read().identity(&dst_fp) {
        id.is_relay
    } else {
        false
    };
    let my_fp = ctx.get(GLOBAL_IDENTITY).public().fingerprint();
    let am_i_relay = if let Some(id) = ctx.get(RELAY_GRAPH).read().identity(&my_fp) {
        id.is_relay
    } else {
        false
    };

    let instructs = route_to_instructs(route.clone(), ctx.get(RELAY_GRAPH).read().deref())?;
    // currently the path for every one of them is the same; will want to change this in the future
    let reverse_route = match reply_route(ctx) {
        Some(r) => r,
        None => return Err(SendMessageError::NoRoute(dst_fp)),
    };

    let reverse_instructs = route_to_instructs(reverse_route, ctx.get(RELAY_GRAPH).read().deref())?;

    let mut rbs: Vec<ReplyBlock> = vec![];
    for _ in 0..count {
        let (rb, (id, degarbler)) = ReplyBlock::new(
            &reverse_instructs,
            first_peeler,
            &ctx.get(GLOBAL_ONION_SK).public(),
            am_i_relay,
            my_anon_osk.clone(),
            my_anon_isk,
        )
        .map_err(|_| SendMessageError::ReplyBlockFailed)?;
        rbs.push(rb);
        ctx.get(DEGARBLERS).insert(id, degarbler);
    }
    let wrapped_rb_onion = RawPacket::new_normal(
        &instructs,
        &dest_opk,
        dest_is_relay,
        InnerPacket::ReplyBlocks(rbs),
        &my_anon_isk,
    )?;

    let emit_time = Instant::now();
    ctx.get(DELAY_QUEUE)
        .insert((wrapped_rb_onion, first_peeler), emit_time);

    Ok(())
}
