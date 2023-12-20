use std::{net::SocketAddr, time::Duration};

use earendil_crypt::Fingerprint;
use smol::{channel::Sender, future::FutureExt};
use smolscale::{immortal::Immortal, reaper::TaskReaper};
use sosistab2::Pipe;
use sosistab2_obfsudp::{ObfsUdpListener, ObfsUdpPipe, ObfsUdpPublic, ObfsUdpSecret};

use crate::daemon::per_route_tasks;

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
    route_task_sender: Sender<Immortal>,
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
        let pipe = listener.accept().await?;
        let context = context.clone();
        let sender = route_task_sender.clone();
        group.attach(smolscale::spawn(async move {
            let route_tasks = per_route_tasks(context.daemon_ctx.clone(), pipe, None).await?;
            for task in route_tasks {
                sender.send(task).await?;
            }
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
    route_task_sender: Sender<Immortal>,
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

            let route_tasks = per_route_tasks(
                context.daemon_ctx.clone(),
                pipe,
                Some(context.remote_fingerprint),
            )
            .await?;

            for task in route_tasks {
                route_task_sender.send(task).await?;
            }
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
