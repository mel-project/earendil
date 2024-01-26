use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use earendil_crypt::Fingerprint;
use futures_util::TryFutureExt;
use nursery_macro::nursery;
use once_cell::sync::OnceCell;
use smol::future::FutureExt;
use smol_timeout::TimeoutExt;

use sosistab2::{Multiplex, MuxSecret, Pipe};
use sosistab2_obfsudp::{ObfsUdpListener, ObfsUdpPipe, ObfsUdpPublic, ObfsUdpSecret};
use tracing::Level;
pub mod chat;
mod gossip;
mod link_connection;
mod link_protocol;

use crate::{
    config::{AutoSettle, LinkPrice},
    daemon::{
        context::{DEBTS, GLOBAL_IDENTITY, NEIGH_TABLE_NEW, SETTLEMENTS},
        inout_route::{
            chat::{add_client, remove_client},
            gossip::gossip_loop,
            link_connection::link_authenticate,
        },
        settlement::{
            difficulty_to_micromel, onchain_multiplier, SettlementProof, SettlementRequest,
        },
    },
};

use self::{
    link_connection::{connection_loop, LinkProtocolImpl, LinkRpcTransport},
    link_protocol::{LinkClient, LinkService},
};

use super::DaemonContext;

const CONNECTION_LIFETIME: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct InRouteContext {
    pub daemon_ctx: DaemonContext,
    pub in_route_name: String,
}

#[tracing::instrument(skip(context, secret))]
pub async fn in_route_obfsudp(
    context: InRouteContext,
    listen: SocketAddr,
    secret: String,
    link_price: LinkPrice,
) -> anyhow::Result<()> {
    let secret = ObfsUdpSecret::from_bytes(*blake3::hash(secret.as_bytes()).as_bytes());
    tracing::debug!(
        "obfsudp in_route {} listen start with cookie {}",
        context.in_route_name,
        hex::encode(secret.to_public().as_bytes())
    );
    let listener = ObfsUdpListener::bind(listen, secret).await?;
    nursery!(loop {
        let pipe = listener.accept().await?;
        let context = context.clone();
        spawn!(
            per_link_loop(context.daemon_ctx.clone(), pipe, None, link_price)
                .timeout(CONNECTION_LIFETIME)
        )
        .detach();
    })
}

#[derive(Clone)]
pub struct OutRouteContext {
    pub daemon_ctx: DaemonContext,
    pub out_route_name: String,
    pub remote_fingerprint: Fingerprint,
}

#[tracing::instrument(skip(context, cookie))]
pub async fn out_route_obfsudp(
    context: OutRouteContext,
    connect: SocketAddr,
    cookie: [u8; 32],
    link_price: LinkPrice,
) -> anyhow::Result<()> {
    let mut timer1 = smol::Timer::interval(CONNECTION_LIFETIME);
    let mut timer2 = smol::Timer::interval(CONNECTION_LIFETIME);
    loop {
        let fallible = async {
            tracing::debug!("{} trying...", context.out_route_name);
            let pipe = ObfsUdpPipe::connect(connect, ObfsUdpPublic::from_bytes(cookie), "").await?;
            tracing::info!("{} pipe connected", context.out_route_name);

            per_link_loop(
                context.daemon_ctx.clone(),
                pipe,
                Some(context.remote_fingerprint),
                link_price,
            )
            .await
        };
        async {
            if let Err(err) = fallible.await {
                tracing::warn!(
                    "obfs out_route {} failed: {:?}",
                    context.out_route_name,
                    err
                );
            }
            (&mut timer1).await;
        }
        .or(async {
            (&mut timer2).await;
        })
        .await;
    }
}

#[tracing::instrument(skip(ctx, pipe, link_price))]
async fn per_link_loop(
    ctx: DaemonContext,
    pipe: impl Pipe,
    their_fp: Option<Fingerprint>,
    link_price: LinkPrice,
) -> anyhow::Result<()> {
    let mplex = Arc::new(Multiplex::new(MuxSecret::generate(), None));
    mplex.add_pipe(pipe);
    let rpc = LinkRpcTransport::new(mplex.clone());
    let _client = LinkClient::from(rpc);

    // service loop
    let service_loop = link_service_loop(ctx.clone(), mplex, their_fp, link_price);
    service_loop
        .map_err(|e| {
            tracing::warn!("link_service_loop for {:?} died: {:?}", their_fp, e);
            e
        })
        .await?;

    Ok(())
}

async fn link_service_loop(
    ctx: DaemonContext,
    mplex: Arc<Multiplex>,
    their_fp: Option<Fingerprint>,
    link_info: LinkPrice,
) -> anyhow::Result<()> {
    tracing::debug!("starting link_service_loop",);
    scopeguard::defer!(tracing::event!(
        Level::DEBUG,
        their_fp = ?their_fp,
        "stopping link_service_loop",
    ));
    let remote_pk_shared = Arc::new(OnceCell::new());
    let service = Arc::new(LinkService(LinkProtocolImpl {
        ctx: ctx.clone(),
        mplex: mplex.clone(),
        remote_pk: remote_pk_shared.clone(),
        max_outgoing_price: link_info.max_outgoing_price,
    }));

    let (send_outgoing, recv_outgoing) = smol::channel::unbounded();
    let connection_loop = connection_loop(service, mplex.clone(), recv_outgoing);

    connection_loop
        .race(async move {
            let neigh_idpk = link_authenticate(mplex.clone(), their_fp).await?;
            let neigh_fp = neigh_idpk.fingerprint();

            remote_pk_shared.set(neigh_idpk).unwrap();

            // register the outgoing channel. This registration eventually expires, but we'll die before that so it's fine.
            // Note that this will overwrite any existing entry, which will close their send_outgoing, which will stop their loop. That is a good thing!
            ctx.get(NEIGH_TABLE_NEW).insert(neigh_fp, send_outgoing);

            let gossip_loop = {
                let rpc = LinkRpcTransport::new(mplex.clone());
                let client = LinkClient::from(rpc);
                gossip_loop(ctx.clone(), neigh_idpk, client)
            };

            let rpc = LinkRpcTransport::new(mplex.clone());
            let client = Arc::new(LinkClient::from(rpc));

            // add link mux to chats mapping and deregister
            add_client(&ctx, neigh_fp, client.clone());
            scopeguard::defer!({
                remove_client(&ctx, &neigh_fp);
            });

            let price_loop = async {
                loop {
                    ctx.get(DEBTS).insert_incoming_price(
                        neigh_fp,
                        link_info.incoming_price,
                        link_info.incoming_debt_limit,
                    );
                    // attempt to push the price
                    if link_info.incoming_price > 0 {
                        client
                            .push_price(link_info.incoming_price, link_info.incoming_debt_limit)
                            .timeout(Duration::from_secs(60))
                            .await
                            .context("push_price timed out")??;
                    }
                    smol::Timer::after(Duration::from_secs(300)).await;
                }
            };

            // include auto_settle_loop if we have provided automatic settlement options in the config
            if let Some(AutoSettle { interval }) = ctx.get(SETTLEMENTS).auto_settle {
                let auto_settle_loop = async {
                    loop {
                        tracing::debug!("starting auto_settle loop!");
                        smol::Timer::after(Duration::from_secs(interval)).await;

                        if let Ok(Some(seed)) = client.request_seed().await {
                            tracing::debug!("got an auto_settle seed");
                            let debts = ctx.get(DEBTS);
                            let net_debt = debts.net_debt_est(&neigh_fp).unwrap_or_default();
                            if net_debt.is_negative() {
                                let i_owe = net_debt.abs();
                                let difficulty =
                                    (i_owe / onchain_multiplier() as i128).ilog2() as usize;

                                let proof = SettlementProof::new_auto(seed, difficulty);
                                let request = SettlementRequest::new(
                                    *ctx.get(GLOBAL_IDENTITY),
                                    difficulty_to_micromel(difficulty),
                                    proof,
                                );
                                match client.start_settlement(request).await {
                                    Ok(Some(_)) => log::debug!(
                                        "automatic settlement of {} micromel accepted by {}",
                                        difficulty_to_micromel(difficulty),
                                        neigh_idpk.fingerprint()
                                    ),
                                    Ok(None) => log::warn!(
                                        "automatic settlement rejected by {}",
                                        neigh_idpk.fingerprint(),
                                    ),
                                    Err(e) => log::warn!(
                                        "error with automatic settlement sent to {}: {e}",
                                        neigh_idpk.fingerprint()
                                    ),
                                }
                            }
                        }
                    }
                };

                gossip_loop.race(price_loop.race(auto_settle_loop)).await
            } else {
                gossip_loop.race(price_loop).await
            }
        })
        .await
}
