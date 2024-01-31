use std::time::Instant;

use anyhow::Context;
use earendil_crypt::Fingerprint;
use earendil_packet::{InnerPacket, PeeledPacket, RawPacket};

use crate::{
    daemon::{
        context::{
            ANON_DESTS, DEBTS, DEGARBLERS, GLOBAL_IDENTITY, GLOBAL_ONION_SK, NEIGH_TABLE_NEW,
        },
        rrb_balance::{decrement_rrb_balance, replenish_rrb},
    },
    socket::Endpoint,
};

use super::context::{DaemonContext, SOCKET_RECV_QUEUES};

#[tracing::instrument(skip(ctx, pkt))]
pub fn peel_forward(ctx: &DaemonContext, last_hop_fp: Fingerprint, pkt: RawPacket) {
    let inner = || {
        if !ctx.get(DEBTS).is_within_debt_limit(&last_hop_fp) {
            anyhow::bail!("received pkt from neighbor who owes us too much money -_-");
        }
        tracing::trace!(
            "peel_forward on raw packet with hash {}",
            blake3::hash(&bytemuck::cast::<RawPacket, [u8; 8882]>(pkt))
        );
        if last_hop_fp != ctx.get(GLOBAL_IDENTITY).public().fingerprint() {
            ctx.get(DEBTS).incr_incoming(last_hop_fp);
            tracing::trace!("incr'ed debt");
        }

        let now = Instant::now();
        let peeled = pkt.peel(ctx.get(GLOBAL_ONION_SK))?;

        scopeguard::defer!(tracing::trace!(
            "message peel forward took {:?}",
            now.elapsed()
        ));
        match peeled {
            PeeledPacket::Forward {
                to: next_hop,
                pkt: inner,
            } => {
                let conn = ctx
                    .get(NEIGH_TABLE_NEW)
                    .get(&next_hop)
                    .context(format!("could not find this next hop {next_hop}"))?;
                let _ = conn.try_send(inner);
                if next_hop != ctx.get(GLOBAL_IDENTITY).public().fingerprint() {
                    ctx.get(DEBTS).incr_outgoing(next_hop);
                }
            }
            PeeledPacket::Received {
                from: src_fp,
                pkt: inner,
            } => process_inner_pkt(
                ctx,
                inner,
                src_fp,
                ctx.get(GLOBAL_IDENTITY).public().fingerprint(),
            )?,
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
