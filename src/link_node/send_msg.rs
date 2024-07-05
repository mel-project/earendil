use std::{sync::Arc, time::Instant};

use anyhow::Context;
use earendil_crypt::RelayFingerprint;
use earendil_packet::RawPacket;
use itertools::Itertools;
use smol::{channel::Sender, lock::Semaphore};

use crate::{
    link_node::{link_protocol::LinkClient, route_util::one_hop_closer},
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

const RIBBON: f64 = 100.0;
pub(super) async fn send_msg(
    link_node_ctx: &LinkNodeCtx,
    to: NodeId,
    msg: LinkMessage,
) -> anyhow::Result<()> {
    let link_w_payinfo = link_node_ctx
        .link_table
        .get(&to)
        .context("no link to this NeighborId")?
        .clone();

    // disable payments if price == 0
    if link_w_payinfo.1.price != 0.0 {
        // check debt & send payment if we are close to the debt limit
        let curr_debt = link_node_ctx.store.get_debt(to).await?;
        let micromels_from_limit = link_w_payinfo.1.debt_limit - curr_debt;
        // pay if we're within 100 µMEL of the debt limit
        if micromels_from_limit <= RIBBON {
            let _guard = link_node_ctx
                .send_task_semaphores
                .entry(to)
                .or_insert_with(|| Arc::new(Semaphore::new(1)))
                .try_acquire_arc();
            let link_node_ctx = link_node_ctx.clone();
            let link_client = LinkClient(link_w_payinfo.0.rpc_transport());
            if let Some(_guard) = _guard {
                smolscale::spawn(async move {
                    let _guard = _guard;
                       let ott = link_client.get_ott().await??;
                    let mut remaining_pay_amt: u64 = (link_w_payinfo.1.debt_limit - curr_debt).abs().ceil() as u64 + 100;
                    let (paysystem, to_payaddr) = link_node_ctx
                        .payment_systems
                            .select(&link_w_payinfo.1.paysystem_name_addrs)
                        .context("no supported payment system")?;
                    let my_id = link_node_ctx.my_id.public();
                    let max_granularity = paysystem.max_granularity();
                    while remaining_pay_amt > 0 {
                        let current_pay_amt = remaining_pay_amt.min(max_granularity);
                        tracing::debug!(
                            "within 100 µMEL of debt limit! curr_debt={curr_debt}; debt_limit={}. SENDING PAYMENT with amt={current_pay_amt}; total_amt={remaining_pay_amt}!",
                            link_w_payinfo.1.debt_limit
                        );
                        match paysystem.pay(my_id, &to_payaddr, current_pay_amt, &ott).await {
                            Ok(proof) => {
                                // send payment proof to remote
                                link_client
                                    .send_payment_proof(
                                        current_pay_amt,
                                        paysystem.name(),
                                        proof.clone(),
                                    )
                                    .await??;
                                tracing::debug!("sent payment proof to remote for amount: {}", current_pay_amt);
                                // decrement our debt to them
                                link_node_ctx
                                    .store
                                    .insert_debt_entry(
                                        to,
                                        DebtEntry {
                                            delta: -(current_pay_amt as f64),
                                            timestamp: chrono::offset::Utc::now().timestamp(),
                                            proof: Some(proof),
                                        },
                                    )
                                    .await?;
                                tracing::debug!("logged payment of amount: {}", current_pay_amt);
                                remaining_pay_amt -= current_pay_amt;
                            }
                            Err(e) => {
                                tracing::warn!("sending payment of {} to {:?} failed with ERR: {e}", current_pay_amt, to);
                            }
                        }
                    }
                    if remaining_pay_amt == 0 {
                        tracing::debug!("Full payment completed successfully!");
                        anyhow::Ok(())
                    } else {
                        tracing::warn!("Payment process incomplete. Remaining amount: {}", remaining_pay_amt);
                        anyhow::bail!("Payment process incomplete")
                    }
                }) 
                .detach();
            }
        };
        // if we are at debt limit, drop packet here since the other side would drop it anyways
        if micromels_from_limit <= 0.0 {
            anyhow::bail!(format!( "AT debt limit with {to}! curr_debt={curr_debt}; debt_limit={} DROPPING outgoing pkt",
            link_w_payinfo.1.debt_limit))
        }
        // if we are quite close to the debt limit, slow down by dropping packets
        else if micromels_from_limit / RIBBON < 0.7 {
            let random_number: f64 = rand::random();
            if random_number < micromels_from_limit / RIBBON {
                // send message to remote
                link_w_payinfo.0.send_msg(msg).await?;
                // increment our debt to them
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
        }
        // otherwise, send the packet
        else {
            link_w_payinfo.0.send_msg(msg).await?;
            // increment our debt to them
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
    } else {
        // debt system not in effect; always sending message!
        link_w_payinfo.0.send_msg(msg).await?;
    }
    Ok(())
}
