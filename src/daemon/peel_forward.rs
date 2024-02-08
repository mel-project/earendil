use std::time::Instant;

use anyhow::Context;
use earendil_crypt::Fingerprint;
use earendil_packet::{InnerPacket, PeeledPacket, RawPacket};

use crate::{
    daemon::{
        context::{
            ANON_DESTS, DEBTS, DEGARBLERS, GLOBAL_IDENTITY, GLOBAL_ONION_SK, NEIGH_TABLE_NEW,
            RELAY_GRAPH,
        },
        rrb_balance::{decrement_rrb_balance, replenish_rrb},
    },
    socket::Endpoint,
};

use super::context::{DaemonContext, SOCKET_RECV_QUEUES};

#[tracing::instrument(skip(ctx, pkt))]
pub fn peel_forward(
    ctx: &DaemonContext,
    last_hop_fp: Fingerprint,
    peeler: Fingerprint,
    pkt: RawPacket,
) {
    let inner = || {
        let my_fp = ctx.get(GLOBAL_IDENTITY).public().fingerprint();
        if !ctx.get(DEBTS).is_within_debt_limit(&last_hop_fp) {
            anyhow::bail!("received pkt from neighbor who owes us too much money -_-");
        }
        tracing::trace!(
            "peel_forward on raw packet with hash {}",
            blake3::hash(&bytemuck::cast::<RawPacket, [u8; 8882]>(pkt))
        );
        if last_hop_fp != my_fp {
            ctx.get(DEBTS).incr_incoming(last_hop_fp);
            tracing::trace!("incr'ed debt");
        }

        if peeler == my_fp {
            // I am the designated peeler, peel and forward towards next peeler
            let now = Instant::now();
            let peeled: PeeledPacket = pkt.peel(ctx.get(GLOBAL_ONION_SK))?;

            scopeguard::defer!(tracing::trace!(
                "message peel forward took {:?}",
                now.elapsed()
            ));
            match peeled {
                PeeledPacket::Forward {
                    to: next_peeler,
                    pkt,
                } => {
                    let maybe_route = ctx
                        .get(RELAY_GRAPH)
                        .read()
                        .find_shortest_path(&my_fp, &next_peeler);

                    if let Some(route) = maybe_route {
                        let next_hop = route[1];
                        let conn = ctx
                            .get(NEIGH_TABLE_NEW)
                            .get(&next_hop)
                            .context(format!("could not find this next hop {next_hop}"))?;

                        let _ = conn.try_send((pkt, next_hop));
                        if next_hop != my_fp {
                            ctx.get(DEBTS).incr_outgoing(next_hop);
                        }
                    } else {
                        log::warn!("no route found to next peeler {next_peeler}");
                    }
                }
                PeeledPacket::Received {
                    from: src_fp,
                    pkt: inner,
                } => process_inner_pkt(ctx, inner, src_fp, my_fp)?,
                PeeledPacket::GarbledReply { id, mut pkt } => {
                    tracing::trace!("received garbled packet");
                    let reply_degarbler = ctx
                        .get(DEGARBLERS)
                        .remove(&id)
                        .context(format!(
                "no degarbler for this garbled pkt with id {id}, despite {} items in the degarbler",
                ctx.get(DEGARBLERS).len()
            ))?
                        .1;
                    let (inner, src_fp) = reply_degarbler.degarble(&mut pkt)?;
                    tracing::trace!("packet has been degarbled!");

                    // TODO
                    decrement_rrb_balance(ctx, reply_degarbler.my_anon_isk(), src_fp);
                    replenish_rrb(ctx, reply_degarbler.my_anon_isk(), src_fp)?;

                    process_inner_pkt(
                        ctx,
                        inner,
                        src_fp,
                        reply_degarbler.my_anon_isk().public().fingerprint(),
                    )?;
                }
            }
        } else {
            // we are not peeler, forward the packet a step closer to peeler
            let maybe_route = ctx
                .get(RELAY_GRAPH)
                .read()
                .find_shortest_path(&my_fp, &peeler);

            if let Some(route) = maybe_route {
                let next_hop = route.get(0).context("empty route, should not happen")?;

                let conn = ctx
                    .get(NEIGH_TABLE_NEW)
                    .get(&next_hop)
                    .context(format!("could not find this next hop {next_hop}"))?;
                let _ = conn.try_send((pkt, peeler));
                if next_hop != &my_fp {
                    ctx.get(DEBTS).incr_outgoing(*next_hop);
                }
            } else {
                log::warn!("no route found, dropping packet");
            }
        }
        Ok(())
    };
    if let Err(err) = inner() {
        tracing::warn!("could not peel_forward: {:?}", err)
    }
}

#[tracing::instrument(skip(ctx, inner))]
fn process_inner_pkt(
    ctx: &DaemonContext,
    inner: InnerPacket,
    src_fp: Fingerprint,
    dest_fp: Fingerprint,
) -> anyhow::Result<()> {
    match inner {
        InnerPacket::Message(msg) => {
            tracing::debug!("received InnerPacket::Message");
            let dest = Endpoint::new(dest_fp, msg.dest_dock);
            if let Some(send_incoming) = ctx.get(SOCKET_RECV_QUEUES).get(&dest) {
                send_incoming.try_send((msg, src_fp))?;
            } else {
                anyhow::bail!("No socket listening on destination {dest}")
            }
        }
        InnerPacket::ReplyBlocks(reply_blocks) => {
            tracing::debug!("received a batch of ReplyBlocks");
            for reply_block in reply_blocks {
                ctx.get(ANON_DESTS).lock().insert(src_fp, reply_block);
            }
        }
    }
    Ok(())
}
