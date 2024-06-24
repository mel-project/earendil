use std::time::Instant;

use anyhow::Context;
use earendil_crypt::RelayFingerprint;
use earendil_packet::RawPacket;
use itertools::Itertools;
use smol::channel::Sender;

use crate::{
    link_node::{link_protocol::LinkClient, route_util::one_hop_closer, types::NodeIdSecret},
    DebtEntry,
};

use super::{
    link::LinkMessage,
    types::{LinkNodeCtx, NodeId},
};

pub(super) async fn send_to_next_peeler(
    link_node_ctx: &LinkNodeCtx,
    emit_time: Option<Instant>,
    next_peeler: RelayFingerprint,
    pkt: RawPacket,
    send_raw: Sender<LinkMessage>,
    my_fp: RelayFingerprint,
) -> anyhow::Result<()> {
    if next_peeler == my_fp {
        tracing::trace!("sending peeled packet to self = next_peeler");
        smolscale::spawn(async move {
            if let Some(emit_time) = emit_time {
                smol::Timer::at(emit_time).await;
            }
            send_raw
                .send(LinkMessage::ToRelay {
                    packet: bytemuck::bytes_of(&pkt).to_vec().into(),
                    next_peeler,
                })
                .await?;
            anyhow::Ok(())
        })
        .detach();
    } else {
        send_to_nonself_next_peeler(link_node_ctx, emit_time, next_peeler, pkt).await?;
    }
    anyhow::Ok(())
}

pub(super) async fn send_to_nonself_next_peeler(
    link_node_ctx: &LinkNodeCtx,
    emit_time: Option<Instant>,
    next_peeler: RelayFingerprint,
    pkt: RawPacket,
) -> anyhow::Result<()> {
    let closer_hop = {
        let graph = link_node_ctx.relay_graph.read();
        let my_neighs = link_node_ctx
            .link_table
            .iter()
            .map(|p| *p.key())
            .filter_map(|p| match p {
                NodeId::Relay(r) => Some(r),
                NodeId::Client(_) => None,
            })
            .collect_vec();
        one_hop_closer(&my_neighs, &graph, next_peeler)?
    };
    tracing::trace!("sending peeled packet to nonself next_peeler = {next_peeler}");
    // TODO delay queue here rather than this inefficient approach
    let link_node_ctx = link_node_ctx.clone();
    smolscale::spawn(async move {
        if let Some(emit_time) = emit_time {
            smol::Timer::at(emit_time).await;
        }
        if let Err(e) = send_msg(
            &link_node_ctx,
            NodeId::Relay(closer_hop),
            LinkMessage::ToRelay {
                packet: bytemuck::bytes_of(&pkt).to_vec().into(),
                next_peeler,
            },
        )
        .await
        {
            tracing::warn!("failed to send message to closer hop: {e}")
        }
        anyhow::Ok(())
    })
    .detach();
    anyhow::Ok(())
}

pub(super) async fn send_msg(
    link_node_ctx: &LinkNodeCtx,
    to: NodeId,
    msg: LinkMessage,
) -> anyhow::Result<()> {
    let link_w_payinfo = link_node_ctx
        .link_table
        .get(&to)
        .context("no link to this NeighborId")?;
    // check debt & send payment if we are close to the debt limit
    let curr_debt = link_node_ctx.store.get_debt(to).await?;

    // pay if we're within 1 MEL of the debt limit
    if link_w_payinfo.1.debt_limit - curr_debt <= 1_000_000 {
        let pay_amt = (link_w_payinfo.1.debt_limit - curr_debt).abs() + 1_000_000;
        tracing::debug!(
            "within 1 MEL of debt limit! curr_debt={curr_debt}; debt_limit={}. SENDING PAYMENT with amt={pay_amt}!",
            link_w_payinfo.1.debt_limit
        );
        // let task = smolscale::spawn();
        let (paysystem, to_payaddr) = link_node_ctx
            .payment_systems
            .select(&link_w_payinfo.1.paysystem_name_addrs)
            .context("no supported payment system")?;
        let my_id = match link_node_ctx.my_id {
            NodeIdSecret::Relay(idsk) => NodeId::Relay(idsk.public().fingerprint()),
            NodeIdSecret::Client(id) => NodeId::Client(id),
        };
        loop {
            match paysystem.pay(my_id, &to_payaddr, pay_amt as _).await {
                Ok(proof) => {
                    // send payment proof to remote
                    LinkClient(link_w_payinfo.0.rpc_transport())
                        .send_payment_proof(pay_amt as _, paysystem.name(), proof.clone())
                        .await??;
                    tracing::debug!("sent payment proof to remote!");
                    // decrement our debt to them
                    link_node_ctx
                        .store
                        .insert_debt_entry(
                            to,
                            DebtEntry {
                                delta: -pay_amt,
                                timestamp: chrono::offset::Utc::now().timestamp(),
                                proof: Some(proof),
                            },
                        )
                        .await?;
                    tracing::debug!("logged payment!");
                    break;
                }
                Err(e) => tracing::warn!("sending payment to {:?} failed with ERR: {e}", to),
            }
        }
    };
    // increment our debt to them
    if link_w_payinfo.1.price > 0 {
        link_node_ctx
            .store
            .insert_debt_entry(
                to,
                DebtEntry {
                    delta: link_w_payinfo.1.price,
                    timestamp: chrono::offset::Utc::now().timestamp(),
                    proof: None,
                },
            )
            .await?;
    }
    link_w_payinfo.0.send_msg(msg).await?;
    Ok(())
}
