mod anon_dest;
mod delay_queue;
mod remote_rb;

use std::time::Instant;

use anyhow::Context;
use bytes::Bytes;
use dashmap::DashMap;
use earendil_crypt::{AnonEndpoint, RelayFingerprint, RemoteId};
use earendil_packet::{
    Dock, ForwardInstruction, InnerPacket, Message, RawBody, RawPacket, ReplyDegarbler,
};
use smol::channel::{Receiver, Sender};

use crate::{
    context::{CtxField, DaemonContext, MY_RELAY_IDENTITY, RELAY_GRAPH},
    n2r::{anon_dest::ANON_DESTS, remote_rb::replenish_remote_rb},
    n2r_socket::RelayEndpoint,
    network::send_raw,
};

static DEGARBLERS: CtxField<DashMap<u64, ReplyDegarbler>> = |_| Default::default();

static INCOMING_BACKWARDS: CtxField<(Sender<(RawBody, u64)>, Receiver<(RawBody, u64)>)> =
    |_| smol::channel::unbounded();

static INCOMING_FORWARDS: CtxField<(
    Sender<(InnerPacket, AnonEndpoint)>,
    Receiver<(InnerPacket, AnonEndpoint)>,
)> = |_| smol::channel::unbounded();

pub async fn incoming_forward(
    ctx: &DaemonContext,
    inner_pkt: InnerPacket,
    anon_remote: AnonEndpoint,
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
    rb_id: u64,
) -> anyhow::Result<()> {
    ctx.get(INCOMING_BACKWARDS).0.send((pkt, rb_id)).await?;
    Ok(())
}

// anon_endpoint is the source, dock is the destination dock
pub async fn read_forward(ctx: &DaemonContext) -> anyhow::Result<(Bytes, AnonEndpoint, Dock)> {
    loop {
        let (inner, anon_remote) = ctx.get(INCOMING_FORWARDS).1.recv().await?;

        match inner {
            InnerPacket::Message(msg) => {
                tracing::debug!("received InnerPacket::Message");
                let anon_endpoint = anon_remote;
                return Ok((msg.body, anon_endpoint, msg.relay_dock));
            }
            InnerPacket::ReplyBlocks(reply_blocks) => {
                tracing::trace!("received a batch of ReplyBlocks");
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
            let anon_endpoint = degarbler.my_anon_id();
            let relay_endpoint = RelayEndpoint::new(relay_fp, msg.relay_dock);
            // consume a reply block
            remote_rb::consume_remote_rb(ctx, anon_endpoint, relay_endpoint.fingerprint);
            Ok((msg.body, relay_endpoint, anon_endpoint))
        }
        InnerPacket::ReplyBlocks(_) => anyhow::bail!("we shouldn't be getting reply blocks here"),
    }
}

/// Sends a raw N2R message with the given parameters.
#[tracing::instrument(skip(ctx, content))]
pub async fn send_forward(
    ctx: &DaemonContext,
    src: AnonEndpoint,
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

    let route = forward_route_to(ctx, dst_fp).context("failed to create forward route")?;
    let first_peeler = *route
        .first()
        .context("empty route, cannot obtain first peeler")?;

    let instructs = route_to_instructs(ctx, &route).context("route_to_instructs failed")?;
    tracing::debug!(
        "*************************** translated this route to instructions: {:?} => {:?}",
        route,
        instructs
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
        InnerPacket::Message(Message::new(dst_dock, content.clone())),
        RemoteId::Anon(src),
    )?;

    replenish_remote_rb(ctx, src, dst_fp)
        .await
        .context("failed to replenish remote reply blocks")?;

    send_raw(ctx, wrapped_onion, first_peeler)
        .await
        .context("send_raw failed")?;

    Ok(())
}

pub async fn send_backward(
    ctx: &DaemonContext,
    src_dock: Dock,
    dst: AnonEndpoint,
    content: Bytes,
) -> anyhow::Result<()> {
    let reply_block = ctx
        .get(ANON_DESTS)
        .lock()
        .pop(&dst)
        .context(format!("no reply block for destination: {dst}"))?;
    let message = Message {
        relay_dock: src_dock,
        body: content,
    };

    let packet = RawPacket::new_reply(
        &reply_block,
        InnerPacket::Message(message.clone()),
        &RemoteId::Relay(
            ctx.get(MY_RELAY_IDENTITY)
                .expect("only relays have global identities")
                .public()
                .fingerprint(),
        ),
    )?;

    send_raw(ctx, packet, reply_block.first_peeler).await?;
    Ok(())
}

fn forward_route_to(
    ctx: &DaemonContext,
    dest_fp: RelayFingerprint,
) -> anyhow::Result<Vec<RelayFingerprint>> {
    let mut route = ctx.get(RELAY_GRAPH).read().rand_relays(2);
    route.push(dest_fp);
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
