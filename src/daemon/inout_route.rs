use std::{net::SocketAddr, time::Duration};

use earendil_crypt::Fingerprint;
use smol::future::FutureExt;
use smolscale::reaper::TaskReaper;
use sosistab2_obfsudp::{ObfsUdpListener, ObfsUdpPipe, ObfsUdpPublic, ObfsUdpSecret};

use crate::daemon::{context::NEIGH_TABLE, link_connection::LinkConnection};

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
) -> anyhow::Result<()> {
    let secret = ObfsUdpSecret::from_bytes(*blake3::hash(secret.as_bytes()).as_bytes());
    log::debug!(
        "obfsudp in_route {} listen start with cookie {}",
        context.in_route_name,
        hex::encode(secret.to_public().as_bytes())
    );
    let listener = ObfsUdpListener::bind(listen, secret).await?;
    let group = TaskReaper::new();
    loop {
        let next = listener.accept().await?;
        let context = context.clone();
        group.attach(smolscale::spawn(async move {
            let connection = LinkConnection::connect(context.daemon_ctx.clone(), next).await?;
            log::info!(
                "obfsudp in_route {} accepted {}",
                context.in_route_name,
                connection.remote_idpk().fingerprint()
            );
            context.daemon_ctx.get(NEIGH_TABLE).insert(
                connection.remote_idpk().fingerprint(),
                connection,
                Duration::from_secs(300),
            );
            anyhow::Ok(())
        }))
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
            let connection = LinkConnection::connect(context.daemon_ctx.clone(), pipe).await?;
            if connection.remote_idpk().fingerprint() != context.remote_fingerprint {
                anyhow::bail!(
                    "remote fingerprint {} different from configured {}",
                    connection.remote_idpk().fingerprint(),
                    context.remote_fingerprint
                )
            }
            context
                .daemon_ctx
                .get(NEIGH_TABLE)
                .insert_pinned(context.remote_fingerprint, connection);
            log::info!("obfsudp out_route {} successful", context.out_route_name);
            anyhow::Ok(())
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
