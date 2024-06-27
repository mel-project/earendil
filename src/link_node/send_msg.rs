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

        // pay if we're within 100 µMEL of the debt limit
        if link_w_payinfo.1.debt_limit - curr_debt <= 100.0 {
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
                    let pay_amt = (link_w_payinfo.1.debt_limit - curr_debt).abs() + 100.0;
                    tracing::debug!(
                    "within 100 µMEL of debt limit! curr_debt={curr_debt}; debt_limit={}. SENDING PAYMENT with amt={pay_amt}!",
                    link_w_payinfo.1.debt_limit
                );
                    let (paysystem, to_payaddr) = link_node_ctx
                        .payment_systems
                        .select(&link_w_payinfo.1.paysystem_name_addrs)
                        .context("no supported payment system")?;
                    let my_id = link_node_ctx.my_id.public();

                    loop {
                        match paysystem.pay(my_id, &to_payaddr, pay_amt as _, &ott).await {
                            Ok(proof) => {
                                // send payment proof to remote
                                link_client
                                    .send_payment_proof(
                                        pay_amt as _,
                                        paysystem.name(),
                                        proof.clone(),
                                    )
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
                                break anyhow::Ok(());
                            }
                            Err(e) => {
                                tracing::warn!("sending payment to {:?} failed with ERR: {e}", to)
                            }
                        }
                    }
                })
                .detach();
            }
        };
        // increment our debt to them
        if link_w_payinfo.1.price > 0.0 {
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
    link_w_payinfo.0.send_msg(msg).await?;
    Ok(())
}
