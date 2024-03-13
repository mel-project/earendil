mod anon_dest;
mod delay_queue;
mod remote_rb;

use std::time::Instant;

use anyhow::Context;
use bytes::Bytes;
use earendil_crypt::{AnonRemote, RelayFingerprint, RemoteId};
use earendil_packet::{Dock, ForwardInstruction, InnerPacket, Message, RawBody, RawPacket};
use smol::channel::{Receiver, Sender};

use crate::{
    context::{CtxField, DaemonContext, DEGARBLERS, RELAY_GRAPH},
    n2r::{anon_dest::ANON_DESTS, delay_queue::DELAY_QUEUE, remote_rb::replenish_rrb},
    socket::{AnonEndpoint, RelayEndpoint},
};

static INCOMING_BACKWARDS: CtxField<(Sender<(RawBody, u64)>, Receiver<(RawBody, u64)>)> =
    |_| smol::channel::unbounded();

static INCOMING_FORWARDS: CtxField<(
    Sender<(InnerPacket, AnonRemote)>,
    Receiver<(InnerPacket, AnonRemote)>,
)> = |_| smol::channel::unbounded();

pub async fn incoming_forward(
    ctx: &DaemonContext,
    inner_pkt: InnerPacket,
    anon_remote: AnonRemote,
) -> anyhow::Result<()> {
    ctx.get(INCOMING_FORWARDS)
        .0
        .send((inner_pkt, anon_remote))
        .await?;
    Ok(())
}

// this is called by link logic
// this reads incoming data and updates local n2r state
pub async fn incoming_backward(
    ctx: &DaemonContext,
    pkt: RawBody,
    degarbler_id: u64,
) -> anyhow::Result<()> {
    ctx.get(INCOMING_BACKWARDS)
        .0
        .send((pkt, degarbler_id))
        .await?;
    Ok(())
}

// anon_endpoint is the source, dock is the destination dock
pub async fn read_forward(ctx: &DaemonContext) -> anyhow::Result<(Bytes, AnonEndpoint, Dock)> {
    loop {
        let (inner, anon_remote) = ctx.get(INCOMING_FORWARDS).1.recv().await?;

        match inner {
            InnerPacket::Message(msg) => {
                tracing::debug!("received InnerPacket::Message");
                let anon_endpoint = AnonEndpoint::new(anon_remote, msg.source_dock);
                return Ok((msg.body, anon_endpoint, msg.dest_dock));
            }
            InnerPacket::ReplyBlocks(reply_blocks) => {
                tracing::debug!("received a batch of ReplyBlocks");
                for reply_block in reply_blocks {
                    ctx.get(ANON_DESTS).lock().insert(anon_remote, reply_block);
                }
            }
        }
    }
}

// called by a loop in `daemon.rs` to send data to the right sockets
pub async fn read_backward(
    ctx: &DaemonContext,
) -> anyhow::Result<(Bytes, RelayEndpoint, AnonEndpoint)> {
    let (mut reply, degarbler_id) = ctx.get(INCOMING_BACKWARDS).1.recv().await?;
    let degarbler = ctx
        .get(DEGARBLERS)
        .remove(&degarbler_id)
        .context("no degarbler for incoming reply")?
        .1;
    let (inner_pkt, relay_fp) = degarbler.degarble(&mut reply)?;
    match inner_pkt {
        InnerPacket::Message(msg) => {
            let anon_endpoint = AnonEndpoint::new(degarbler.my_anon_id(), msg.dest_dock);
            let relay_endpoint = RelayEndpoint::new(relay_fp, msg.source_dock);
            Ok((msg.body, relay_endpoint, anon_endpoint))
        }
        InnerPacket::ReplyBlocks(_) => anyhow::bail!("we shouldn't be getting reply blocks here"),
    }
}

/// Sends a raw N2R message with the given parameters.
#[tracing::instrument(skip(ctx, content))]
pub async fn send_forward(
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

pub async fn send_backward(
    ctx: &DaemonContext,
    src_dock: Dock,
    dst: AnonRemote,
    dst_dock: Dock,
    content: Bytes,
) -> anyhow::Result<()> {
    todo!();
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
