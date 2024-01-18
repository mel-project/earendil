use std::{
    ops::Deref,
    time::{Duration, Instant},
};

use bytes::Bytes;
use dashmap::DashMap;
use earendil_crypt::{Fingerprint, IdentitySecret};
use earendil_packet::{
    crypt::OnionSecret, Dock, InnerPacket, Message, RawPacket, ReplyBlock, ReplyDegarbler,
};
use earendil_topology::RelayGraph;

use itertools::Itertools;
use moka::sync::{Cache, CacheBuilder};
use once_cell::sync::Lazy;
use parking_lot::{Mutex, RwLock};
use smol::channel::Sender;

use crate::{
    config::ConfigFile, control_protocol::SendMessageError, daemon::route_to_instructs,
    socket::Endpoint,
};

use super::{
    db::db_read, debts::Debts, peel_forward::peel_forward, reply_block_store::ReplyBlockStore,
    rrb_balance::replenish_rrb,
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
                tracing::warn!("**** INIT RELAY GRAPH****");
                RwLock::new(RelayGraph::new())
            }
        }
    })
};
pub static ANON_DESTS: CtxField<Mutex<ReplyBlockStore>> = |_| Mutex::new(ReplyBlockStore::new());

pub static NEIGH_TABLE_NEW: CtxField<Cache<Fingerprint, Sender<RawPacket>>> = |_| {
    CacheBuilder::default()
        .time_to_live(Duration::from_secs(120))
        .build()
}; // TODO a better solution for deletion
pub static SOCKET_RECV_QUEUES: CtxField<DashMap<Endpoint, Sender<(Message, Fingerprint)>>> =
    |_| Default::default();
pub static DEGARBLERS: CtxField<Cache<u64, ReplyDegarbler>> = |_| {
    CacheBuilder::default()
        .time_to_live(Duration::from_secs(60))
        .build()
};

pub static DEBTS: CtxField<Debts> = |ctx| {
    let ctx = ctx.clone();
    smol::future::block_on(async move {
        match db_read(&ctx, "debts").await {
            Ok(Some(debts)) => {
                tracing::warn!("retrieving persisted debts");
                match Debts::from_bytes(debts) {
                    Ok(debts) => debts,
                    Err(e) => {
                        tracing::warn!("debt decode error: {e}");
                        Debts::new()
                    }
                }
            }
            _ => {
                tracing::warn!("initializing debts");
                Debts::new()
            }
        }
    })
};

/// Sends a raw N2R message with the given parameters.
pub async fn send_n2r(
    ctx: &DaemonContext,
    src_idsk: IdentitySecret,
    src_dock: Dock,
    dst_fp: Fingerprint,
    dst_dock: Dock,
    content: Vec<Bytes>,
) -> Result<(), SendMessageError> {
    let now = Instant::now();
    let _guard = scopeguard::guard((), |_| {
        let send_msg_time = now.elapsed();
        tracing::trace!("send message took {:?}", send_msg_time);
    });

    let src_anon = &src_idsk != ctx.get(GLOBAL_IDENTITY);

    let maybe_reply_block = ctx.get(ANON_DESTS).lock().pop(&dst_fp);
    if let Some(reply_block) = maybe_reply_block {
        if src_anon {
            return Err(SendMessageError::NoAnonId);
        }
        let inner = InnerPacket::Message(Message::new(src_dock, dst_dock, content));
        let raw_packet = RawPacket::new_reply(&reply_block, inner, &src_idsk)?;
        peel_forward(
            ctx,
            ctx.get(GLOBAL_IDENTITY).public().fingerprint(),
            raw_packet,
        );
    } else {
        let route = ctx
            .get(RELAY_GRAPH)
            .read()
            .find_shortest_path(&ctx.get(GLOBAL_IDENTITY).public().fingerprint(), &dst_fp)
            .ok_or(SendMessageError::NoRoute(dst_fp))?;
        let instructs = {
            let graph = ctx.get(RELAY_GRAPH).read();
            route_to_instructs(route, &graph)
        }?;
        let their_opk = ctx
            .get(RELAY_GRAPH)
            .read()
            .identity(&dst_fp)
            .ok_or(SendMessageError::NoOnionPublic(dst_fp))?
            .onion_pk;
        let wrapped_onion = RawPacket::new_normal(
            &instructs,
            &their_opk,
            InnerPacket::Message(Message::new(src_dock, dst_dock, content)),
            &src_idsk,
        )?;

        // if anon source, send RBs
        if src_anon {
            replenish_rrb(ctx, src_idsk, dst_fp)?;
        }

        // we send the onion by treating it as a message addressed to ourselves
        peel_forward(
            ctx,
            ctx.get(GLOBAL_IDENTITY).public().fingerprint(),
            wrapped_onion,
        );
    }
    Ok(())
}

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

    let route = ctx
        .get(RELAY_GRAPH)
        .read()
        .find_shortest_path(&ctx.get(GLOBAL_IDENTITY).public().fingerprint(), &dst_fp)
        .ok_or(SendMessageError::NoRoute(dst_fp))?;
    let their_opk = ctx
        .get(RELAY_GRAPH)
        .read()
        .identity(&dst_fp)
        .ok_or(SendMessageError::NoOnionPublic(dst_fp))?
        .onion_pk;
    let instructs = route_to_instructs(route.clone(), ctx.get(RELAY_GRAPH).read().deref())?;
    // currently the path for every one of them is the same; will want to change this in the future
    let reverse_route = ctx
        .get(RELAY_GRAPH)
        .read()
        .find_shortest_path(&dst_fp, &ctx.get(GLOBAL_IDENTITY).public().fingerprint())
        .ok_or(SendMessageError::NoRoute(dst_fp))?;
    let reverse_instructs = route_to_instructs(reverse_route, ctx.get(RELAY_GRAPH).read().deref())?;

    let mut rbs: Vec<ReplyBlock> = vec![];
    for _ in 0..count {
        let (rb, (id, degarbler)) = ReplyBlock::new(
            &reverse_instructs,
            &ctx.get(GLOBAL_ONION_SK).public(),
            my_anon_osk.clone(),
            my_anon_isk,
        )
        .map_err(|_| SendMessageError::ReplyBlockFailed)?;
        rbs.push(rb);
        ctx.get(DEGARBLERS).insert(id, degarbler);
    }
    let wrapped_rb_onion = RawPacket::new_normal(
        &instructs,
        &their_opk,
        InnerPacket::ReplyBlocks(rbs),
        &my_anon_isk,
    )?;
    tracing::trace!(
        "inject_asif_incoming on route = {:?}",
        route.iter().map(|s| s.to_string()).collect_vec()
    );
    // we send the onion by treating it as a message addressed to ourselves
    peel_forward(
        ctx,
        ctx.get(GLOBAL_IDENTITY).public().fingerprint(),
        wrapped_rb_onion,
    );
    Ok(())
}
