mod remote_rb;

use std::time::Instant;

use anyhow::Context;
use bytes::Bytes;
use earendil_crypt::{AnonRemote, RelayFingerprint, RemoteId};
use earendil_packet::{Dock, ForwardInstruction, InnerPacket, Message, RawPacket};

use crate::{
    daemon::context::{DaemonContext, DELAY_QUEUE, RELAY_GRAPH},
    n2r::remote_rb::replenish_rrb,
};

/// Sends a raw N2R message with the given parameters.
#[tracing::instrument(skip(ctx, content))]
pub async fn n2r_send(
    ctx: &DaemonContext,
    src: AnonRemote,
    src_dock: Dock,
    dst_fp: RelayFingerprint,
    dst_dock: Dock,
    content: Bytes,
) -> anyhow::Result<()> {
    tracing::debug!("calling send_n2r here");
    let now = Instant::now();
    let _guard = scopeguard::guard((), |_| {
        let send_msg_time = now.elapsed();
        tracing::trace!("send message took {:?}", send_msg_time);
    });

    let route = forward_route(ctx)?;
    let first_peeler = route[0];

    let instructs = route_to_instructs(ctx, &route)?;
    tracing::trace!(
        "*************************** translated this route to instructions: {:?}",
        route
    );
    let dest_opk = ctx
        .get(RELAY_GRAPH)
        .read()
        .identity(&dst_fp)
        .context("couldn't get the identity of the destination fp")?
        .onion_pk;
    let wrapped_onion = RawPacket::new_normal(
        &instructs,
        &dest_opk,
        InnerPacket::Message(Message::new(src_dock, dst_dock, content.clone())),
        RemoteId::Anon(src),
    )?;

    replenish_rrb(ctx, src, dst_fp)?;

    let emit_time = Instant::now();
    ctx.get(DELAY_QUEUE)
        .insert((wrapped_onion, first_peeler), emit_time);

    Ok(())
}

fn forward_route(ctx: &DaemonContext) -> anyhow::Result<Vec<RelayFingerprint>> {
    let route = ctx.get(RELAY_GRAPH).read().rand_relays(3);
    tracing::debug!("forward route formed: {:?}", route);
    Ok(route)
}

fn route_to_instructs(
    ctx: &DaemonContext,
    route: &[RelayFingerprint],
) -> anyhow::Result<Vec<ForwardInstruction>> {
    route
        .windows(2)
        .map(|wind| {
            let this = wind[0];
            let next = wind[1];

            let this_pubkey = ctx
                .get(RELAY_GRAPH)
                .read()
                .identity(&this)
                .context("failed to get an identity somewhere in our route")?
                .onion_pk;
            Ok(ForwardInstruction {
                this_pubkey,
                next_hop: next,
            })
        })
        .collect()
}
