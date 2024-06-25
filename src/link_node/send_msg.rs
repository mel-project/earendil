use std::{
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use earendil_crypt::RelayFingerprint;
use earendil_packet::RawPacket;
use itertools::Itertools;
use smol::{channel::Sender, lock::RwLock};

use crate::{
    link_node::{link_protocol::LinkClient, route_util::one_hop_closer, types::NodeIdSecret},
    DebtEntry, LinkStore,
};

use super::{
    link::Link,
    link::LinkMessage,
    payment_system::PaymentSystem,
    types::NodeId,
    types::{LinkNodeCtx, LinkPaymentInfo},
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
            Arc::new(link_node_ctx),
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

async fn perform_payment(
    store: Arc<LinkStore>,
    to: NodeId,
    pay_amt: u64,
    payment_id: &str,
    curr_debt: i64,
    paysystem: Arc<Box<dyn PaymentSystem>>,
    to_payaddr: String,
    my_id: NodeId,
    link_w_payinfo: Arc<(Arc<Link>, LinkPaymentInfo)>,
) -> anyhow::Result<String> {
    loop {
        match paysystem
            .pay(my_id, &to_payaddr, pay_amt as _, payment_id)
            .await
        {
            Ok(proof) => {
                // send payment proof to remote
                LinkClient(link_w_payinfo.0.rpc_transport())
                    .send_payment_proof(pay_amt as _, paysystem.name(), proof.clone())
                    .await??;
                println!("sent payment!");
                // decrement our debt to them
                store
                    .insert_debt_entry(
                        to,
                        DebtEntry {
                            delta: -curr_debt,
                            timestamp: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .expect("time went backwards")
                                .as_secs() as i64,
                            proof: Some(proof.clone()),
                        },
                    )
                    .await?;
                tracing::debug!("SUCCESSFULLY SENT PAYMENT!");
                return Ok(proof);
            }
            Err(e) => tracing::warn!("sending payment to {:?} failed with ERR: {e}", to),
        }
    }
}

pub(super) async fn initiate_payment_if_needed(
    link_node_ctx: Arc<LinkNodeCtx>,
    to: NodeId,
) -> anyhow::Result<()> {
    let link_w_payinfo = link_node_ctx
        .link_table
        .get(&to)
        .context("no link to this NeighborId")?
        .clone();
    let curr_debt = link_node_ctx.store.get_debt(to).await?;

    if link_w_payinfo.1.debt_limit - curr_debt <= 1_000_000 {
        let link_client = LinkClient(link_w_payinfo.0.rpc_transport());
        let ott = link_client.get_ott().await??;
        let pay_amt = (link_w_payinfo.1.debt_limit - curr_debt).abs() + 1_000_000;
        tracing::debug!(
            "within 1 MEL of debt limit! curr_debt={curr_debt}; debt_limit={}. SENDING PAYMENT with amt={pay_amt}!",
            link_w_payinfo.1.debt_limit
        );

        let (paysystem, to_payaddr) = link_node_ctx
            .payment_systems
            .select(&link_w_payinfo.1.paysystem_name_addrs)
            .context("no supported payment system")?;
        let my_id = match &link_node_ctx.my_id {
            NodeIdSecret::Relay(idsk) => NodeId::Relay(idsk.public().fingerprint()),
            NodeIdSecret::Client(id) => NodeId::Client(*id),
        };

        let link_store = link_node_ctx.store.clone();
        let payment_task = smolscale::spawn(async move {
            perform_payment(
                link_store,
                to,
                pay_amt as u64,
                &ott,
                curr_debt,
                paysystem,
                to_payaddr,
                my_id,
                Arc::new(link_w_payinfo),
            )
            .await
        });

        link_node_ctx
            .payments
            .entry(to)
            .or_insert_with(|| smol::lock::RwLock::new(payment_task));
    }

    Ok(())
}

pub(super) async fn send_msg(
    link_node_ctx: Arc<LinkNodeCtx>,
    to: NodeId,
    msg: LinkMessage,
) -> anyhow::Result<()> {
    initiate_payment_if_needed(link_node_ctx.clone(), to).await?;

    let link_w_payinfo = link_node_ctx
        .link_table
        .get(&to)
        .context("no link to this NeighborId")?;

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
