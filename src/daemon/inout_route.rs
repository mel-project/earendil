use std::{net::SocketAddr, time::Duration};

use clone_macro::clone;
use earendil_crypt::Fingerprint;
use futures_util::TryFutureExt;
use smol::future::FutureExt;
use smolscale::immortal::{Immortal, RespawnStrategy};
use sosistab2::Pipe;
use sosistab2_obfsudp::{ObfsUdpListener, ObfsUdpPipe, ObfsUdpPublic, ObfsUdpSecret};

use crate::{
    daemon::{context::NEIGH_TABLE, gossip::gossip_loop, link_connection::LinkConnection},
    log_error,
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
) -> anyhow::Result<()> {
    let secret = ObfsUdpSecret::from_bytes(*blake3::hash(secret.as_bytes()).as_bytes());
    log::debug!(
        "obfsudp in_route {} listen start with cookie {}",
        context.in_route_name,
        hex::encode(secret.to_public().as_bytes())
    );
    let listener = ObfsUdpListener::bind(listen, secret).await?;
    loop {
        let pipe = listener.accept().await?;
        let context = context.clone();
        smolscale::spawn(per_route_tasks(context.daemon_ctx.clone(), pipe, None)).detach();
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

            smolscale::spawn(per_route_tasks(
                context.daemon_ctx.clone(),
                pipe,
                Some(context.remote_fingerprint),
            ))
            .detach();

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

async fn per_route_tasks(
    ctx: DaemonContext,
    pipe: impl Pipe,
    their_fp: Option<Fingerprint>,
) -> anyhow::Result<()> {
    let link_info = LinkConnection::connect(ctx.clone(), pipe).await?;

    if let Some(fp) = their_fp {
        let remote_fp = link_info.remote_pk.fingerprint();
        log::info!("about to insert into neightable for fp: {}", fp);

        if fp != remote_fp {
            anyhow::bail!(
                "out route fingerprint in config ({}), does not match link fingerprint: {}",
                fp,
                remote_fp,
            );
        }

        ctx.get(NEIGH_TABLE).insert_pinned(fp, link_info.conn);
        log::info!("inserted out_route link for {}", fp);
    } else {
        ctx.get(NEIGH_TABLE).insert(
            link_info.conn.remote_idpk().fingerprint(),
            link_info.conn.clone(),
            Duration::from_secs(300),
        );
        log::info!(
            "inserted in_route link for {}",
            link_info.conn.remote_idpk.fingerprint()
        );
    }

    // Race the connection task against the gossip loop
    let connection_task = async {
        link_info.connection_task.await;
        anyhow::Ok(())
    };

    // Wrap the gossip loop in an async block
    let gossip_task = async {
        gossip_loop(ctx.clone(), link_info.remote_pk, link_info.client.clone()).await?;
        anyhow::Ok(())
    };

    connection_task
        .race(gossip_loop(
            ctx.clone(),
            link_info.remote_pk,
            link_info.client.clone(),
        ))
        .await?;

    // connection_task.race(gossip_task).await?;

    Ok(())
}
