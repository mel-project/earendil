use std::{net::SocketAddr, time::Duration};

use earendil_crypt::Fingerprint;
use smol::future::FutureExt;
use smolscale::reaper::TaskReaper;
use sosistab2::Pipe;
use sosistab2_obfsudp::{ObfsUdpListener, ObfsUdpPipe, ObfsUdpPublic, ObfsUdpSecret};

use crate::{
    config::LinkPrice,
    daemon::{
        context::{DEBTS, NEIGH_TABLE},
        gossip::gossip_loop,
        link_connection::LinkConnection,
    },
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
        tasks.attach(smolscale::spawn(per_route_tasks(
            context.daemon_ctx.clone(),
            pipe,
            None,
            link_price.clone(),
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
    let tasks = TaskReaper::new();
    loop {
        let fallible = async {
            log::debug!("obfsudp out_route {} trying...", context.out_route_name);
            let pipe = ObfsUdpPipe::connect(connect, ObfsUdpPublic::from_bytes(cookie), "").await?;
            log::info!(
                "obfsudp out_route {} pipe connected",
                context.out_route_name
            );

            tasks.attach(smolscale::spawn(per_route_tasks(
                context.daemon_ctx.clone(),
                pipe,
                Some(context.remote_fingerprint),
                link_price.clone(),
            )));

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
    link_price: LinkPrice,
) -> anyhow::Result<()> {
    let link_info =
        LinkConnection::connect(ctx.clone(), pipe, link_price.max_outgoing_price).await?;

    if let Some(fp) = their_fp {
        let remote_fp = link_info.conn.remote_idpk.fingerprint();
        log::info!("about to insert into neightable for fp: {}", fp);

        if fp != remote_fp {
            anyhow::bail!(
                "out route fingerprint in config ({}), does not match link fingerprint: {}",
                fp,
                remote_fp,
            );
        }

        link_info
            .client
            .push_price(link_price.incoming_price, link_price.incoming_debt_limit)
            .await?;
        ctx.get(DEBTS).insert_incoming_price(
            link_info.conn.remote_idpk().fingerprint(),
            link_price.incoming_price,
            link_price.incoming_debt_limit,
        );

        ctx.get(NEIGH_TABLE)
            .insert_pinned(fp, link_info.conn.clone());
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
        link_info.task.await;
        anyhow::Ok(())
    };

    connection_task
        .race(gossip_loop(
            ctx.clone(),
            link_info.conn.remote_idpk,
            link_info.client,
        ))
        .await?;

    // connection_task.race(gossip_task).await?;

    Ok(())
}
