use std::time::Instant;

use anyhow::Context;
use earendil_crypt::Fingerprint;
use earendil_packet::{InnerPacket, PeeledPacket};

use crate::socket::Endpoint;

use super::context::DaemonContext;

/// Loop that takes incoming packets, peels them, and processes them
pub async fn peel_forward_loop(ctx: DaemonContext) -> anyhow::Result<()> {
    loop {
        let pkt = ctx.table.recv_raw_packet().await;
        let now = Instant::now();
        let peeled = pkt.peel(&ctx.onion_sk)?;

        scopeguard::defer!(log::debug!("message peel forward took {:?}", now.elapsed()));
        match peeled {
            PeeledPacket::Forward {
                to: next_hop,
                pkt: inner,
            } => {
                let conn = ctx
                    .table
                    .lookup(&next_hop)
                    .context("could not find this next hop")?;
                conn.send_raw_packet(inner).await;
            }
            PeeledPacket::Received {
                from: src_fp,
                pkt: inner,
            } => process_inner_pkt(&ctx, inner, src_fp, ctx.identity.public().fingerprint())?,
            PeeledPacket::GarbledReply { id, mut pkt } => {
                log::trace!("received garbled packet");
                let reply_degarbler = ctx
                    .degarblers
                    .get(&id)
                    .context("no degarbler for this garbled pkt")?;
                let (inner, src_fp) = reply_degarbler.degarble(&mut pkt)?;
                log::trace!("packet has been degarbled!");
                ctx.decrement_rrb_balance(reply_degarbler.my_anon_isk(), src_fp);
                ctx.replenish_reply_blocks(reply_degarbler.my_anon_isk(), src_fp)
                    .await?;
                // ctx.send_reply_blocks(2, reply_degarbler.my_anon_isk(), src_fp)
                //     .await?;
                process_inner_pkt(
                    &ctx,
                    inner,
                    src_fp,
                    reply_degarbler.my_anon_isk().public().fingerprint(),
                )?;
            }
        }
    }
}

fn process_inner_pkt(
    ctx: &DaemonContext,
    inner: InnerPacket,
    src_fp: Fingerprint,
    dest_fp: Fingerprint,
) -> anyhow::Result<()> {
    match inner {
        InnerPacket::Message(msg) => {
            // log::debug!("received InnerPacket::Message: {:?}", msg);
            let dest = Endpoint::new(dest_fp, msg.dest_dock);
            if let Some(send_incoming) = ctx.socket_recv_queues.get(&dest) {
                send_incoming.try_send((msg, src_fp))?;
            } else {
                anyhow::bail!("No socket listening on destination {dest}")
            }
        }
        InnerPacket::ReplyBlocks(reply_blocks) => {
            log::trace!("received a batch of ReplyBlocks");
            for reply_block in reply_blocks {
                ctx.anon_destinations.lock().insert(src_fp, reply_block);
            }
        }
    }
    Ok(())
}
