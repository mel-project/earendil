use std::time::{Duration, Instant};

use anyhow::Context;
use dashmap::DashSet;
use earendil_crypt::{NeighborId, RelayFingerprint};
use earendil_packet::{PeeledPacket, RawPacket};

use crate::{
    context::{
        CtxField, DaemonContext, CLIENT_TABLE, GLOBAL_IDENTITY, GLOBAL_ONION_SK, NEIGH_TABLE_NEW,
        RELAY_GRAPH,
    },
    n2r,
};

/// Dumps a raw packet onto the network with its next peeler, trying our best to have it go in the right direction.
pub async fn send_raw(
    ctx: &DaemonContext,
    packet: RawPacket,
    next_peeler: RelayFingerprint,
) -> anyhow::Result<()> {
    if ctx.init().is_client() {
        let next_hop = one_hop_closer(&ctx, next_peeler).context("failed to get next hop")?;
        let conn = ctx
            .get(NEIGH_TABLE_NEW)
            .get(&next_hop)
            .context(format!("could not find this next hop {next_hop}"))
            .context("unable to find next_hop from neighbor table")?;
        conn.send((packet, next_hop))
            .await
            .context("failed to send packet to next hop")?;
    } else {
        let my_fp = ctx
            .get(GLOBAL_IDENTITY)
            .expect("only relays have global identities")
            .public()
            .fingerprint();

        if next_peeler == my_fp {
            // todo: don't allow ourselves to be the first hop when choosing forward routes
            let _ = incoming_raw(&ctx, NeighborId::Relay(my_fp), next_peeler, packet).await;
        } else {
            let next_hop = one_hop_closer(&ctx, next_peeler)?;
            let conn = ctx
                .get(NEIGH_TABLE_NEW)
                .get(&next_hop)
                .context(format!("could not find this next hop {next_hop}"))?;

            conn.send((packet, next_peeler)).await?;
        }
    }
    Ok(())
}

#[tracing::instrument(skip(ctx, pkt))]
pub async fn incoming_raw(
    ctx: &DaemonContext,
    last_hop: NeighborId,
    next_peeler: RelayFingerprint,
    pkt: RawPacket,
) -> anyhow::Result<()> {
    static PKTS_SEEN: CtxField<DashSet<blake3::Hash>> = |_| DashSet::new();

    let my_fp = ctx
        .get(GLOBAL_IDENTITY)
        .expect("only relays have global identities")
        .public()
        .fingerprint();

    let pkts_seen = ctx.get(PKTS_SEEN);
    let packet_hash = blake3::hash(bytemuck::bytes_of(&pkt));

    if !pkts_seen.insert(packet_hash) {
        anyhow::bail!("received replayed pkt {packet_hash}");
    }

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
            PeeledPacket::Relay {
                next_peeler,
                pkt,
                delay_ms,
            } => {
                let emit_time = Instant::now() + Duration::from_millis(delay_ms as u64);
                todo!("put a delay queue here")
            }
            PeeledPacket::Received { from, pkt } => {
                n2r::incoming_forward(ctx, pkt, from).await?;
            }
            PeeledPacket::GarbledReply { id, pkt, client_id } => {
                tracing::debug!(
                    id,
                    client_id,
                    "got a GARBLED REPLY to FORWARD to the CLIENT!!!"
                );
                if let Some(client_link) = ctx.get(CLIENT_TABLE).get(&client_id) {
                    client_link.send((pkt, id)).await?;
                } else {
                    tracing::warn!(
                        "oh NOOO there is NOO client! Here are the clients that we DO have:"
                    );
                    for c in ctx.get(CLIENT_TABLE).iter() {
                        tracing::warn!("  {}", c.0);
                    }
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
        let next_hop = one_hop_closer(ctx, next_peeler)?;
        let conn = ctx
            .get(NEIGH_TABLE_NEW)
            .get(&next_hop)
            .context(format!("could not find this next hop {next_hop}"))?;
        conn.send((pkt, next_peeler)).await?;
    }
    Ok(())
}

fn one_hop_closer(ctx: &DaemonContext, dest: RelayFingerprint) -> anyhow::Result<RelayFingerprint> {
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

    next_hop.context("cannot route one hop closer since there's no neighbors")
}
