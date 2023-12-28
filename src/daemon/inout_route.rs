use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use earendil_crypt::Fingerprint;
use futures_util::TryFutureExt;
use once_cell::sync::OnceCell;
use smol::future::FutureExt;
use smol_timeout::TimeoutExt;
use smolscale::reaper::TaskReaper;
use sosistab2::{Multiplex, MuxSecret, Pipe};
use sosistab2_obfsudp::{ObfsUdpListener, ObfsUdpPipe, ObfsUdpPublic, ObfsUdpSecret};
use tracing::Level;
mod gossip;
mod link_connection;
mod link_protocol;

use crate::{
    config::LinkPrice,
    daemon::{
        context::{DEBTS, NEIGH_TABLE_NEW},
        inout_route::{gossip::gossip_loop, link_connection::link_authenticate},
    },
};

use self::{
    link_connection::{connection_loop, LinkProtocolImpl, LinkRpcTransport},
    link_protocol::{LinkClient, LinkService},
};

use super::DaemonContext;

#[derive(Clone)]
pub struct InRouteContext {
    pub daemon_ctx: DaemonContext,
    pub in_route_name: String,
}

pub async fn in_route_obfsudp(
    context: InRouteContext,
    listen: SocketAddr,
    secret: String,
    link_price: LinkPrice,
) -> anyhow::Result<()> {
    let secret = ObfsUdpSecret::from_bytes(*blake3::hash(secret.as_bytes()).as_bytes());
    log::debug!(
        "obfsudp in_route {} listen start with cookie {}",
        context.in_route_name,
        hex::encode(secret.to_public().as_bytes())
    );
    let listener = ObfsUdpListener::bind(listen, secret).await?;
    let tasks = TaskReaper::new();
    loop {
        let pipe = listener.accept().await?;
        let context = context.clone();
        tasks.attach(smolscale::spawn(per_link_loop(
            context.daemon_ctx.clone(),
            pipe,
            None,
            link_price,
        )));
    }
}

#[derive(Clone)]
pub struct OutRouteContext {
    pub daemon_ctx: DaemonContext,
    pub out_route_name: String,
    pub remote_fingerprint: Fingerprint,
}

pub async fn out_route_obfsudp(
    context: OutRouteContext,
    connect: SocketAddr,
    cookie: [u8; 32],
    link_price: LinkPrice,
) -> anyhow::Result<()> {
    const CONNECTION_LIFETIME: Duration = Duration::from_secs(60);

    let mut timer1 = smol::Timer::interval(CONNECTION_LIFETIME);
    let mut timer2 = smol::Timer::interval(CONNECTION_LIFETIME);
    loop {
        let fallible = async {
            log::debug!("obfsudp out_route {} trying...", context.out_route_name);
            let pipe = ObfsUdpPipe::connect(connect, ObfsUdpPublic::from_bytes(cookie), "").await?;
            log::info!(
                "obfsudp out_route {} pipe connected",
                context.out_route_name
            );

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
                log::warn!(
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

#[tracing::instrument(skip(pipe, link_price))]
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
            log::warn!("link_service_loop for {:?} died: {:?}", their_fp, e);
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
    tracing::event!(
        Level::DEBUG,
        their_fp = ?their_fp,
        "starting link_service_loop",
    );
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
            let idpk = link_authenticate(mplex.clone(), their_fp).await?;
            remote_pk_shared.set(idpk).unwrap();

            // register the outgoing channel, and deregister when we die
            ctx.get(NEIGH_TABLE_NEW)
                .insert(idpk.fingerprint(), send_outgoing);
            scopeguard::defer!({
                ctx.get(NEIGH_TABLE_NEW).remove(&idpk.fingerprint());
            });

            let gossip_loop = {
                let rpc = LinkRpcTransport::new(mplex.clone());
                let client = LinkClient::from(rpc);
                gossip_loop(ctx.clone(), idpk, client)
            };

            let rpc = LinkRpcTransport::new(mplex.clone());
            let client = LinkClient::from(rpc);

            let price_loop = async {
                loop {
                    ctx.get(DEBTS).insert_incoming_price(
                        idpk.fingerprint(),
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
            gossip_loop.race(price_loop).await
        })
        .await
}
