use std::time::{Duration, Instant};

use anyhow::Context;
use earendil_crypt::{AnonDest, NodeId, RelayFingerprint, SourceId};
use earendil_packet::{InnerPacket, PeeledPacket, RawPacket, RAW_PACKET_SIZE};

use crate::{
    daemon::context::{
        ANON_DESTS, CLIENT_SOCKET_RECV_QUEUES, CLIENT_TABLE, DEBTS, DELAY_QUEUE, GLOBAL_IDENTITY,
        GLOBAL_ONION_SK, NEIGH_TABLE_NEW, PKTS_SEEN, RELAY_GRAPH, RELAY_SOCKET_RECV_QUEUES,
    },
    socket::{AnonEndpoint, RelayEndpoint},
};

use super::context::DaemonContext;

#[tracing::instrument(skip(ctx, pkt))]
pub async fn peel_forward(
    ctx: &DaemonContext,
    last_hop: NodeId,
    next_peeler: RelayFingerprint,
    pkt: RawPacket,
) {
    let my_fp = ctx
        .get(GLOBAL_IDENTITY)
        .expect("only relays have global identities")
        .public()
        .fingerprint();
    let inner = async {
        let pkts_seen = ctx.get(PKTS_SEEN);
        let packet_hash = blake3::hash(&bytemuck::cast::<RawPacket, [u8; RAW_PACKET_SIZE]>(pkt));

        if pkts_seen.contains(&packet_hash) {
            anyhow::bail!("received replayed pkt {packet_hash}");
        } else {
            pkts_seen.insert(packet_hash);
        }

        match last_hop {
            NodeId::Relay(fp) => {
                if !ctx.get(DEBTS).relay_is_within_debt_limit(&fp) {
                    anyhow::bail!("received pkt from neighbor {fp} who owes us too much money -_-");
                }

                if fp != my_fp {
                    ctx.get(DEBTS).incr_relay_incoming(fp);
                    tracing::trace!("incr'ed relay debt");
                }
            }
            NodeId::Client(id) => {
                if !ctx.get(DEBTS).client_is_within_debt_limit(&id) {
                    anyhow::bail!("received pkt from client {id} who owes us too much money -_-");
                }

                ctx.get(DEBTS).incr_client_incoming(id);
                tracing::trace!("incr'ed client debt");
            }
        };

        tracing::debug!(
            packet_hash = packet_hash.to_string(),
            my_fp = my_fp.to_string(),
            peeler = next_peeler.to_string(),
            "peel_forward on raw packet"
        );

        if next_peeler == my_fp {
            // I am the designated peeler, peel and forward towards next peeler
            let now = Instant::now();
            let peeled: PeeledPacket = pkt.peel(ctx.get(GLOBAL_ONION_SK))?;

            scopeguard::defer!(tracing::trace!(
                "message peel forward took {:?}",
                now.elapsed()
            ));

            match peeled {
                PeeledPacket::Forward {
                    next_peeler,
                    pkt,
                    delay_ms,
                } => {
                    let emit_time = Instant::now() + Duration::from_millis(delay_ms as u64);
                    ctx.get(DELAY_QUEUE).insert((pkt, next_peeler), emit_time);
                }
                PeeledPacket::Received { from, pkt } => {
                    relay_process_inner_pkt(ctx, pkt, from, my_fp)?
                }
                PeeledPacket::GarbledReply { id, pkt, client_id } => {
                    if let Some(client_link) = ctx.get(CLIENT_TABLE).get(&client_id) {
                        client_link.send((pkt, id)).await?;
                    }
                }
            }
        } else {
            tracing::debug!(
                packet_hash = packet_hash.to_string(),
                peeler = next_peeler.to_string(),
                "we are not the peeler"
            );
            // we are not peeler, forward the packet a step closer to peeler

            if let Some(next_hop) = relay_one_hop_closer(ctx, next_peeler) {
                let conn = ctx
                    .get(NEIGH_TABLE_NEW)
                    .get(&next_hop)
                    .context(format!("could not find this next hop {next_hop}"))?;
                let _ = conn.try_send((pkt, next_peeler));
            } else {
                log::warn!("no route found, dropping packet");
            }
        }
        Ok(())
    };
    if let Err(err) = inner.await {
        tracing::warn!("could not peel_forward: {:?}", err)
    }
}

pub fn client_one_hop_closer(
    ctx: &DaemonContext,
    dest: RelayFingerprint,
) -> Option<RelayFingerprint> {
    let my_neighs: Vec<RelayFingerprint> = ctx
        .get(NEIGH_TABLE_NEW)
        .iter()
        .map(|neigh| *neigh.0)
        .collect();

    let mut shortest_route_len = usize::MAX;
    let mut next_hop = None;

    for neigh in my_neighs {
        if let Some(route) = ctx
            .get(RELAY_GRAPH)
            .read()
            .find_shortest_path(&neigh, &dest)
        {
            if route.len() < shortest_route_len {
                shortest_route_len = route.len();
                next_hop = Some(neigh);
            }
        }
    }

    next_hop
}

pub fn relay_one_hop_closer(
    ctx: &DaemonContext,
    dest_fp: RelayFingerprint,
) -> Option<RelayFingerprint> {
    let route = ctx.get(RELAY_GRAPH).read().find_shortest_path(
        &ctx.get(GLOBAL_IDENTITY)
            .expect("only relays have global identities")
            .public()
            .fingerprint(),
        &dest_fp,
    )?;
    route.get(1).cloned()
}

#[tracing::instrument(skip(ctx, inner))]
pub fn client_process_inner_pkt(
    ctx: &DaemonContext,
    inner: InnerPacket,
    src: RelayFingerprint,
    anon_dest: AnonDest,
) -> anyhow::Result<()> {
    match inner {
        InnerPacket::Message(msg) => {
            tracing::debug!("client received InnerPacket::Message");
            let dest = AnonEndpoint::new(anon_dest, msg.dest_dock);
            if let Some(send_incoming) = ctx.get(CLIENT_SOCKET_RECV_QUEUES).get(&dest) {
                send_incoming.try_send((msg, SourceId::Relay(src)))?;
            } else {
                anyhow::bail!("No socket listening on destination {dest}")
            }
        }
        InnerPacket::ReplyBlocks(_reply_blocks) => {
            tracing::warn!("clients shouldn't receive reply blocks");
        }
    }
    Ok(())
}

#[tracing::instrument(skip(ctx, inner))]
fn relay_process_inner_pkt(
    ctx: &DaemonContext,
    inner: InnerPacket,
    src: SourceId,
    dest_fp: RelayFingerprint,
) -> anyhow::Result<()> {
    match inner {
        InnerPacket::Message(msg) => {
            tracing::debug!("received InnerPacket::Message");
            let dest = RelayEndpoint::new(dest_fp, msg.dest_dock);
            if let Some(send_incoming) = ctx.get(RELAY_SOCKET_RECV_QUEUES).get(&dest) {
                send_incoming.try_send((msg, src))?;
            } else {
                anyhow::bail!("No socket listening on destination {dest}")
            }
        }
        InnerPacket::ReplyBlocks(reply_blocks) => {
            tracing::debug!("received a batch of ReplyBlocks");
            for reply_block in reply_blocks {
                if let SourceId::Anon(dest) = src {
                    ctx.get(ANON_DESTS).lock().insert(dest, reply_block);
                } else {
                    anyhow::bail!("no anon dest found for received reply blocks");
                }
            }
        }
    }
    Ok(())
}
