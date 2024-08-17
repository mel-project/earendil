use std::time::{Duration, Instant};

use ahash::AHashSet;
use anyhow::Context;
use earendil_crypt::RelayIdentitySecret;
use earendil_packet::{PeeledPacket, RawPacket};
use earendil_topology::IdentityDescriptor;
use smol::{
    channel::{Receiver, Sender},
    future::FutureExt,
};

use crate::{
    link_node::{
        inout_route::process_in_route,
        send_msg::{self, send_to_next_peeler, send_to_nonself_next_peeler},
    },
    NeighborId, NeighborIdSecret,
};

use super::{link::LinkMessage, types::LinkNodeCtx, IncomingMsg};

pub async fn relay_loop(
    ctx: LinkNodeCtx,
    send_raw: Sender<LinkMessage>,
    recv_raw: Receiver<LinkMessage>,
    send_incoming: Sender<IncomingMsg>,
) -> anyhow::Result<()> {
    let my_idsk = if let NeighborIdSecret::Relay(my_idsk) = &ctx.my_id {
        my_idsk
    } else {
        smol::future::pending().await
    };
    let identity_refresh_loop = async {
        loop {
            let exit_info = &ctx.cfg.exit_info;
            let myself = IdentityDescriptor::new(my_idsk, &ctx.my_onion_sk, exit_info.clone());
            tracing::debug!(
                "inserting ourselves: {} into relay graph with exit: {:?}",
                my_idsk.public().fingerprint(),
                exit_info
            );
            ctx.relay_graph.write().insert_identity(myself)?;
            smol::Timer::after(Duration::from_secs(1)).await;
        }
    };

    let in_loop = in_loop(&ctx, &send_raw);

    let peel_loop = peel_loop(&ctx, my_idsk, &send_raw, recv_raw, send_incoming);

    identity_refresh_loop.race(in_loop).race(peel_loop).await
}

async fn in_loop(ctx: &LinkNodeCtx, send_raw: &Sender<LinkMessage>) -> anyhow::Result<()> {
    let (_, in_routes) = &ctx.cfg.relay_config.as_ref().unwrap();
    if !in_routes.is_empty() {
        futures_util::future::try_join_all(in_routes.iter().map(|(name, in_route)| {
            process_in_route(ctx.clone(), name, in_route, send_raw.clone())
        }))
        .await?;
        Ok(())
    } else {
        smol::future::pending().await
    }
}

async fn peel_loop(
    ctx: &LinkNodeCtx,
    my_idsk: &RelayIdentitySecret,
    send_raw: &Sender<LinkMessage>,
    recv_raw: Receiver<LinkMessage>,
    send_incoming: Sender<IncomingMsg>,
) -> anyhow::Result<()> {
    let mut raw_dedup = AHashSet::new();

    loop {
        let fallible = async {
            match recv_raw.recv().await? {
                LinkMessage::ToRelay {
                    packet,
                    next_peeler,
                } => {
                    if !raw_dedup.insert(blake3::hash(&packet)) {
                        anyhow::bail!("already processed this packet")
                    }
                    tracing::debug!(
                        next_peeler = display(next_peeler),
                        myself = display(my_idsk.public().fingerprint()),
                        "peeling and forwarding",
                    );
                    let packet: &RawPacket = bytemuck::try_from_bytes(&packet)
                        .ok()
                        .context("could not cast")?;

                    // relay pkt
                    if next_peeler != my_idsk.public().fingerprint() {
                        // forward pkt without delay
                        send_to_nonself_next_peeler(ctx, None, next_peeler, *packet).await?
                    } else {
                        let peeled: PeeledPacket = packet.peel(&ctx.my_onion_sk)?;

                        match peeled {
                            PeeledPacket::Relay {
                                next_peeler,
                                pkt,
                                delay_ms,
                            } => {
                                tracing::trace!(
                                    "received a PeeledPacket::Relay for next_peeler = {next_peeler}"
                                );
                                let emit_time =
                                    Instant::now() + Duration::from_millis(delay_ms as u64);
                                send_to_next_peeler(
                                    ctx,
                                    Some(emit_time),
                                    next_peeler,
                                    pkt,
                                    send_raw.clone(),
                                    my_idsk.public().fingerprint(),
                                )
                                .await?;
                            }
                            PeeledPacket::Received { from, pkt } => {
                                tracing::trace!("received a PeeledPacket::Received from = {from}");
                                send_incoming
                                    .send(IncomingMsg::Forward { from, body: pkt })
                                    .await?;
                            }
                            PeeledPacket::GarbledReply {
                                rb_id,
                                pkt,
                                client_id,
                            } => {
                                if client_id == 0 {
                                    tracing::trace!(
                                        rb_id = rb_id,
                                        "received a PeeledPacket::GarbledReply for MYSELF"
                                    );
                                    send_incoming
                                        .send(IncomingMsg::Backward {
                                            rb_id,
                                            body: pkt.to_vec().into(),
                                        })
                                        .await?;
                                } else {
                                    tracing::trace!(
                                        rb_id,
                                        client_id,
                                        "received a PeeledPacket::GarbledReply for a CLIENT"
                                    );
                                    let ctx = ctx.clone();
                                    smolscale::spawn(async move {
                                        if let Err(e) = send_msg::send_msg(
                                            &ctx,
                                            NeighborId::Client(client_id),
                                            LinkMessage::ToClient {
                                                body: pkt.to_vec().into(),
                                                rb_id,
                                            },
                                        )
                                        .await
                                        {
                                            tracing::warn!(
                                                err = debug(e),
                                                "error sending garbled reply to client"
                                            );
                                        }
                                        anyhow::Ok(())
                                    })
                                    .detach();
                                }
                            }
                        }
                    }
                }
                LinkMessage::ToClient { body: _, rb_id: _ } => {
                    anyhow::bail!("Relay received LinkMessage::ToClient")
                }
            }
            anyhow::Ok(())
        };
        if let Err(err) = fallible.await {
            tracing::error!(err = debug(err), "error in relay_peel_loop");
        }
    }
}
