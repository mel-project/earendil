use earendil_crypt::{AnonRemote, RelayFingerprint, RemoteId};
use earendil_packet::{InnerPacket, RawPacket, ReplyBlock};
use moka::sync::Cache;
use parking_lot::Mutex;
use rand::prelude::*;
use std::time::Duration;

use crate::{
    context::{CtxField, DaemonContext, MY_CLIENT_ID, RELAY_GRAPH},
    control_protocol::SendMessageError,
    n2r::{forward_route, route_to_instructs, DEGARBLERS},
    network::{all_relay_neighs, send_raw},
};

static LAWK: Mutex<()> = Mutex::new(());

/// Call to replenish remote reply blocks as needed.
pub fn replenish_remote_rb(
    ctx: &DaemonContext,
    my_anon_id: AnonRemote,
    dst_fp: RelayFingerprint,
) -> Result<(), SendMessageError> {
    let _guard = LAWK.lock();
    const BATCH_SIZE: usize = 5;
    while rb_balance(ctx, my_anon_id, dst_fp) < 100.0 {
        // we conservatively assume half get there
        ctx.get(BALANCE_TABLE).insert(
            (my_anon_id, dst_fp),
            rb_balance(ctx, my_anon_id, dst_fp) + (BATCH_SIZE / 2) as f64,
        );
        let ctx = ctx.clone();
        smolscale::spawn(async move {
            send_reply_blocks(&ctx, BATCH_SIZE, my_anon_id, dst_fp)
                .await
                .inspect_err(|e| {
                    tracing::warn!(error = debug(e), "reply blocks FAILED TO SEND!!!!!")
                })
        })
        .detach();
    }
    Ok(())
}

/// Decrements the estimate of how many reply blocks the other side has. If needed, replenishes too.
pub fn consume_remote_rb(
    ctx: &DaemonContext,
    my_anon_id: AnonRemote,
    reply_source: RelayFingerprint,
) {
    let new_balance = rb_balance(ctx, my_anon_id, reply_source);
    ctx.get(BALANCE_TABLE)
        .insert((my_anon_id, reply_source), new_balance - 1.0);
    replenish_remote_rb(ctx, my_anon_id, reply_source);
}

fn rb_balance(ctx: &DaemonContext, my_anon_id: AnonRemote, reply_source: RelayFingerprint) -> f64 {
    ctx.get(BALANCE_TABLE)
        .get_with((my_anon_id, reply_source), || 0.0)
}

static BALANCE_TABLE: CtxField<Cache<(AnonRemote, RelayFingerprint), f64>> = |_| {
    Cache::builder()
        .time_to_live(Duration::from_secs(60)) // we don't keep track beyond so if rb calculation is wrong, we don't get stuck for too long
        .build()
};

#[tracing::instrument(skip(ctx))]
/// Send a batch of reply blocks to the given N2R destination.
async fn send_reply_blocks(
    ctx: &DaemonContext,
    count: usize,
    my_anon_id: AnonRemote,
    dst_fp: RelayFingerprint,
) -> anyhow::Result<()> {
    tracing::trace!("sending a batch of {count} reply blocks to {dst_fp}");

    let route = forward_route(ctx)?;
    let first_peeler = route[0];

    let dest_opk = ctx
        .get(RELAY_GRAPH)
        .read()
        .identity(&dst_fp)
        .ok_or(SendMessageError::NoOnionPublic(dst_fp))?
        .onion_pk;

    let instructs = route_to_instructs(ctx, &route)?;
    // currently the path for every one of them is the same; will want to change this in the future
    let reverse_route = reply_route(ctx)?;

    let reverse_instructs = route_to_instructs(ctx, &reverse_route)?;

    let mut rbs: Vec<ReplyBlock> = vec![];
    for _ in 0..count {
        let (rb, (id, degarbler)) = ReplyBlock::new(
            &reverse_instructs,
            reverse_route[0],
            &dest_opk,
            *ctx.get(MY_CLIENT_ID),
            my_anon_id,
        )
        .map_err(|e| SendMessageError::ReplyBlockFailed(e.to_string()))?;
        rbs.push(rb);
        ctx.get(DEGARBLERS).insert(id, degarbler);
    }
    let wrapped_rb_onion = RawPacket::new_normal(
        &instructs,
        &dest_opk,
        InnerPacket::ReplyBlocks(rbs),
        RemoteId::Anon(my_anon_id),
    )?;

    send_raw(ctx, wrapped_rb_onion, first_peeler).await?;

    tracing::debug!("****** OHHHH SENTTTT REPPPPLY BLOOOCKS *****");

    Ok(())
}

fn reply_route(ctx: &DaemonContext) -> anyhow::Result<Vec<RelayFingerprint>> {
    let mut route = ctx.get(RELAY_GRAPH).read().rand_relays(3);
    let my_neighs: Vec<RelayFingerprint> = all_relay_neighs(ctx);
    let rand_neigh = my_neighs.choose(&mut rand::thread_rng()).copied();

    match rand_neigh {
        Some(neigh) => route.push(neigh),
        None => anyhow::bail!("we don't have any neighbors, so we cannot plot a reply route"),
    }

    tracing::debug!("reply route formed: {:?}", route);
    Ok(route)
}
