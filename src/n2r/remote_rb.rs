use anyhow::Context;
use earendil_crypt::{AnonEndpoint, RelayFingerprint, RemoteId};
use earendil_packet::{InnerPacket, RawPacket, ReplyBlock};
use moka::sync::Cache;
use parking_lot::Mutex;
use rand::prelude::*;
use std::time::Duration;

use crate::{
    context::{CtxField, DaemonContext, MY_CLIENT_ID, RELAY_GRAPH},
    n2r::{forward_route_to, route_to_instructs, DEGARBLERS},
    network::{all_relay_neighs, send_raw},
};

static LAWK: Mutex<()> = Mutex::new(());

/// Call to replenish remote reply blocks as needed.
pub async fn replenish_remote_rb(
    ctx: &DaemonContext,
    my_anon_id: AnonEndpoint,
    dst_fp: RelayFingerprint,
) -> anyhow::Result<()> {
    const BATCH_SIZE: usize = 5;
    let mut count = 0;
    {
        let _guard = LAWK.lock();
        while rb_balance(ctx, my_anon_id, dst_fp) < 100.0 {
            // we conservatively assume half get there
            ctx.get(BALANCE_TABLE).insert(
                (my_anon_id, dst_fp),
                rb_balance(ctx, my_anon_id, dst_fp) + (BATCH_SIZE / 2) as f64,
            );
            count += 1;
        }
    }
    for _ in 0..count {
        send_reply_blocks(ctx, BATCH_SIZE, my_anon_id, dst_fp).await?;
    }
    Ok(())
}

/// Decrements the estimate of how many reply blocks the other side has. If needed, replenishes too.
pub async fn consume_remote_rb(
    ctx: &DaemonContext,
    my_anon_id: AnonEndpoint,
    reply_source: RelayFingerprint,
) {
    let new_balance = rb_balance(ctx, my_anon_id, reply_source);
    ctx.get(BALANCE_TABLE)
        .insert((my_anon_id, reply_source), new_balance - 1.0);
    let _ = replenish_remote_rb(ctx, my_anon_id, reply_source).await;
}

fn rb_balance(
    ctx: &DaemonContext,
    my_anon_id: AnonEndpoint,
    reply_source: RelayFingerprint,
) -> f64 {
    ctx.get(BALANCE_TABLE)
        .get_with((my_anon_id, reply_source), || 0.0)
}

static BALANCE_TABLE: CtxField<Cache<(AnonEndpoint, RelayFingerprint), f64>> = |_| {
    Cache::builder()
        .time_to_live(Duration::from_secs(60)) // we don't keep track beyond so if rb calculation is wrong, we don't get stuck for too long
        .build()
};

#[tracing::instrument(skip(ctx))]
/// Send a batch of reply blocks to the given N2R destination.
async fn send_reply_blocks(
    ctx: &DaemonContext,
    count: usize,
    my_anon_id: AnonEndpoint,
    dst_fp: RelayFingerprint,
) -> anyhow::Result<()> {
    tracing::trace!("sending a batch of {count} reply blocks for {my_anon_id} to {dst_fp}");

    let route = forward_route_to(ctx, dst_fp).context("failed to form forward route")?;
    let first_peeler = route[0];

    let dest_opk = ctx
        .get(RELAY_GRAPH)
        .read()
        .identity(&dst_fp)
        .context("failed to lookup destination identity")?
        .onion_pk;

    let instructs = route_to_instructs(ctx, &route).context("failed to translate forward route")?;
    // currently the path for every one of them is the same; will want to change this in the future
    let reverse_route = reply_route(ctx).context("failed to form reply route")?;
    let rb_dest_opk = ctx
        .get(RELAY_GRAPH)
        .read()
        .identity(reverse_route.last().context("reverse route no last")?)
        .context("cannot lookup identity of neighbor")?
        .onion_pk;

    let reverse_instructs =
        route_to_instructs(ctx, &reverse_route).context("failed to translate reply route")?;

    let mut rbs: Vec<ReplyBlock> = vec![];
    for _ in 0..count {
        let (rb, (id, degarbler)) = ReplyBlock::new(
            &reverse_instructs,
            reverse_route[0],
            &rb_dest_opk,
            *ctx.get(MY_CLIENT_ID),
            my_anon_id,
        )
        .context("cannot build reply block")?;
        rbs.push(rb);
        ctx.get(DEGARBLERS).insert(id, degarbler);
    }
    let wrapped_rb_onion = RawPacket::new_normal(
        &instructs,
        &dest_opk,
        InnerPacket::ReplyBlocks(rbs),
        RemoteId::Anon(my_anon_id),
    )?;

    send_raw(ctx, wrapped_rb_onion, first_peeler)
        .await
        .context("cannot send raw")?;

    tracing::trace!("****** OHHHH SENTTTT REPPPPLY BLOOOCKS *****");

    Ok(())
}

fn reply_route(ctx: &DaemonContext) -> anyhow::Result<Vec<RelayFingerprint>> {
    let mut route = ctx.get(RELAY_GRAPH).read().rand_relays(2);
    let my_neighs: Vec<RelayFingerprint> = all_relay_neighs(ctx);
    let rand_neigh = my_neighs.choose(&mut rand::thread_rng()).copied();

    match rand_neigh {
        Some(neigh) => route.push(neigh),
        None => anyhow::bail!("we don't have any neighbors, so we cannot plot a reply route"),
    }

    tracing::trace!("reply route formed: {:?}", route);
    Ok(route)
}
