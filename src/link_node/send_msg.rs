use std::{sync::Arc, time::{Duration, Instant}};

use anyhow::Context;
use earendil_crypt::RelayFingerprint;
use earendil_packet::RawPacket;
use itertools::Itertools;
use smol::{channel::Sender, lock::Semaphore};

use crate::link_node::{link_protocol::LinkClient, route_util::one_hop_closer};

use super::{
    link::LinkMessage,
    types::{LinkNodeCtx, NeighborId},
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
                NeighborId::Relay(r) => Some(r),
                NeighborId::Client(_) => None,
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
            NeighborId::Relay(closer_hop),
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

const RIBBON: f64 = 100_000.0;
pub(super) async fn send_msg(
    link_node_ctx: &LinkNodeCtx,
    neighbor: NeighborId,
    msg: LinkMessage,
) -> anyhow::Result<()> {
    let (link, info) = link_node_ctx
        .link_table
        .get(&neighbor)
        .context("no link to this NeighborId")?
        .clone();

    // disable payments if price == 0
    if info.price != 0.0 {
        // check debt & send payment if we are close to the debt limit
        let curr_debt = link_node_ctx.store.get_debt(neighbor).await?;
        // pay if we're within RIBBON µMEL of the debt limit
        if curr_debt > info.debt_limit - RIBBON {
            // we're in the ribbon, so we slow down
            let random_number: f64 = rand::random();
            let drop_prob = (1.0 - (info.debt_limit - curr_debt) / RIBBON).powi(2);
            if random_number < drop_prob {
                tracing::trace!("CLOSE to debt limit; dropped packet probabilistically!");
            } else {
                // send message to remote
                link.send_msg(msg).await?;
                // increment our debt to them
                link_node_ctx
                    .store
                    .delta_debt(neighbor, info.price, None)
                    .await?;
            }
            let _guard = link_node_ctx
                .send_task_semaphores
                .entry(neighbor)
                .or_insert_with(|| Arc::new(Semaphore::new(1)))
                .try_acquire_arc();
            let link_node_ctx = link_node_ctx.clone();
            let link_client = LinkClient(link.rpc_transport());
            if let Some(_guard) = _guard {
                smolscale::spawn(async move {
                    let _guard = _guard;
                       let ott = link_client.get_ott().await??;
                    let mut remaining_pay_amt: u64 = (info.debt_limit - curr_debt).abs().ceil() as u64 + RIBBON as u64;
                    let (paysystem, to_payaddr) = link_node_ctx
                        .payment_systems
                            .select(&info.paysystem_name_addrs)
                        .context("no supported payment system")?;
                    let my_id = link_node_ctx.my_id.public();
                    let max_granularity = paysystem.max_granularity();
                    while remaining_pay_amt > 0 {
                        let current_pay_amt = remaining_pay_amt.min(max_granularity);
                        tracing::debug!(
                            "within {RIBBON} µMEL of debt limit! curr_debt={curr_debt}; debt_limit={}. SENDING PAYMENT with amt={current_pay_amt}; total_amt={remaining_pay_amt}!",
                            info.debt_limit
                        );
                        match paysystem.pay(my_id, &to_payaddr, current_pay_amt, &ott).await {
                            Ok(proof) => {
                                // send payment proof to remote
                                loop {
                                    match link_client
                                    .send_payment_proof(
                                        current_pay_amt,
                                        paysystem.name(),
                                        proof.clone(),
                                    )
                                    .await {
                                        Ok(Ok(_)) => break,
                                        Ok(Err(e)) => tracing::warn!("send_payment_proof() LinkRpcError: {e}"),
                                        Err(e) => tracing::warn!("send_payment_proof() LinkError: {e}"),
                                    }
                                    smol::Timer::after(Duration::from_secs(1)).await;
                                }
                                tracing::debug!("sent payment proof to remote for amount: {}", current_pay_amt);
                                // decrement our debt to them
                                link_node_ctx
                                    .store
                                    .delta_debt(
                                        neighbor,
                                             -(current_pay_amt as f64),
                                           Some(proof)
                                        
                                    )
                                    .await?;
                                tracing::debug!("logged payment of amount: {}", current_pay_amt);
                                remaining_pay_amt -= current_pay_amt;
                            }
                            Err(e) => {
                                tracing::warn!("sending payment of {} to {:?} failed with ERR: {e}", current_pay_amt, neighbor);
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
        }
        // otherwise, send the packet
        else {
            link.send_msg(msg).await?;
            // increment our debt to them
            link_node_ctx
                .store
                .delta_debt(neighbor, info.price, None)
                .await?;
        }
    } else {
        // debt system not in effect; always sending message!
        link.send_msg(msg).await?;
    }
    Ok(())
}
