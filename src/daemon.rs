mod anon_identities;
mod control_protocol_impl;
mod gossip;
mod inout_route;
mod n2n_connection;
mod n2n_protocol;
mod neightable;
mod reply_block_store;

use anyhow::Context;
use bytes::Bytes;
use clone_macro::clone;
use concurrent_queue::ConcurrentQueue;
use earendil_crypt::{Fingerprint, IdentitySecret};
use earendil_packet::ReplyDegarbler;
use earendil_packet::{crypt::OnionSecret, InnerPacket, PeeledPacket};
use earendil_topology::RelayGraph;
use futures_util::{stream::FuturesUnordered, StreamExt, TryFutureExt};
use moka::sync::Cache;
use nanorpc_http::server::HttpRpcServer;
use parking_lot::RwLock;
use smolscale::immortal::{Immortal, RespawnStrategy};

use std::{path::Path, sync::Arc, time::Duration};

use crate::daemon::anon_identities::AnonIdentities;
use crate::daemon::reply_block_store::ReplyBlockStore;
use crate::{
    config::{ConfigFile, InRouteConfig, OutRouteConfig},
    control_protocol::ControlService,
    daemon::{
        gossip::gossip_loop,
        inout_route::{in_route_obfsudp, out_route_obfsudp, InRouteContext, OutRouteContext},
        neightable::NeighTable,
    },
};

use self::control_protocol_impl::ControlProtocolImpl;

fn log_error<E>(label: &str) -> impl FnOnce(E) + '_
where
    E: std::fmt::Debug,
{
    move |s| log::warn!("{label} restart, error: {:?}", s)
}

pub fn main_daemon(config: ConfigFile) -> anyhow::Result<()> {
    fn read_identity(path: &Path) -> anyhow::Result<IdentitySecret> {
        Ok(stdcode::deserialize(&hex::decode(std::fs::read(path)?)?)?)
    }

    fn write_identity(path: &Path, identity: &IdentitySecret) -> anyhow::Result<()> {
        let encoded_identity = hex::encode(stdcode::serialize(&identity)?);
        std::fs::write(path, encoded_identity)?;
        Ok(())
    }

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("earendil=trace"))
        .init();
    let identity = loop {
        match read_identity(&config.identity) {
            Ok(id) => break id,
            Err(err) => {
                log::warn!(
                    "(re)writing identity file at {:?} due to error reading: {:?}",
                    config.identity,
                    err
                );
                let new_id = IdentitySecret::generate();
                write_identity(&config.identity, &new_id)?;
            }
        }
    };
    log::info!(
        "daemon starting with fingerprint {}",
        identity.public().fingerprint()
    );

    smolscale::block_on(async move {
        let table = Arc::new(NeighTable::new());

        let daemon_ctx = DaemonContext {
            config: Arc::new(config),
            table: table.clone(),
            identity: identity.into(),
            onion_sk: OnionSecret::generate(),
            relay_graph: Arc::new(RwLock::new(RelayGraph::new())),
            incoming: Arc::new(ConcurrentQueue::unbounded()),
            degarblers: Cache::new(1_000_000),
            anon_destinations: Arc::new(RwLock::new(ReplyBlockStore::new())),
            anon_identities: Arc::new(RwLock::new(AnonIdentities::new())),
        };

        // Run the loops
        let _table_gc = Immortal::spawn(clone!([table], async move {
            loop {
                smol::Timer::after(Duration::from_secs(60)).await;
                table.garbage_collect();
            }
        }));

        let _peel_forward = Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([daemon_ctx], move || peel_forward_loop(daemon_ctx.clone())
                .map_err(log_error("peel_forward"))),
        );
        let _gossip = Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([daemon_ctx], move || gossip_loop(daemon_ctx.clone())
                .map_err(log_error("gossip"))),
        );
        let _control_protocol = Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([daemon_ctx], move || control_protocol_loop(
                daemon_ctx.clone()
            )
            .map_err(log_error("control_protocol"))),
        );

        let mut route_tasks = FuturesUnordered::new();

        // For every in_routes block, spawn a task to handle incoming stuff
        for (in_route_name, config) in daemon_ctx.config.in_routes.iter() {
            let context = InRouteContext {
                in_route_name: in_route_name.clone(),
                daemon_ctx: daemon_ctx.clone(),
            };
            match config.clone() {
                InRouteConfig::Obfsudp { listen, secret } => {
                    route_tasks.push(smolscale::spawn(in_route_obfsudp(context, listen, secret)));
                }
            }
        }

        // For every out_routes block, spawn a task to handle outgoing stuff
        for (out_route_name, config) in daemon_ctx.config.out_routes.iter() {
            match config {
                OutRouteConfig::Obfsudp {
                    fingerprint,
                    connect,
                    cookie,
                } => {
                    let context = OutRouteContext {
                        out_route_name: out_route_name.clone(),
                        remote_fingerprint: *fingerprint,
                        daemon_ctx: daemon_ctx.clone(),
                    };
                    route_tasks.push(smolscale::spawn(out_route_obfsudp(
                        context, *connect, *cookie,
                    )));
                }
            }
        }

        // Join all the tasks. If any of the tasks terminate with an error, that's fatal!
        while let Some(next) = route_tasks.next().await {
            next?;
        }
        Ok(())
    })
}

/// Loop that handles the control protocol
async fn control_protocol_loop(ctx: DaemonContext) -> anyhow::Result<()> {
    let http = HttpRpcServer::bind(ctx.config.control_listen).await?;
    let service = ControlService(ControlProtocolImpl::new(ctx));
    http.run(service).await?;
    Ok(())
}

/// Loop that takes incoming packets, peels them, and processes them
async fn peel_forward_loop(ctx: DaemonContext) -> anyhow::Result<()> {
    fn process_inner_pkt(
        ctx: &DaemonContext,
        inner: InnerPacket,
        source: Fingerprint,
    ) -> anyhow::Result<()> {
        match inner {
            InnerPacket::Message(msg) => {
                log::debug!("received InnerPacket::Message");
                ctx.incoming.push((msg, source))?;
            }
            InnerPacket::ReplyBlocks(reply_blocks) => {
                log::debug!("received a batch of ReplyBlocks");

                for reply_block in reply_blocks {
                    ctx.anon_destinations
                        .write()
                        .get_or_insert_mut(source, reply_block);
                }
            }
        }
        Ok(())
    }

    loop {
        let pkt = ctx.table.recv_raw_packet().await;
        log::debug!("received raw packet");
        let peeled = pkt.peel(&ctx.onion_sk)?;
        log::debug!("peeled packet!");
        match peeled {
            PeeledPacket::Forward {
                to: next_hop,
                pkt: inner,
            } => {
                let conn = ctx
                    .table
                    .lookup(&next_hop)
                    .context("could not find this next hop")?;
                conn.send_raw_packet(inner).await;
            }
            PeeledPacket::Received {
                from: source,
                pkt: inner,
            } => process_inner_pkt(&ctx, inner, source)?,
            PeeledPacket::GarbledReply { id, mut pkt } => {
                log::debug!("received garbled packet");
                let reply_degarbler = ctx
                    .degarblers
                    .get(&id)
                    .context("no degarbler for this garbled pkt")?;
                let (inner, source) = reply_degarbler.degarble(&mut pkt)?;
                log::debug!("packet has been degarbled!");
                process_inner_pkt(&ctx, inner, source)?
            }
        }
    }
}

#[allow(unused)]
#[derive(Clone)]
pub struct DaemonContext {
    config: Arc<ConfigFile>,
    table: Arc<NeighTable>,
    identity: Arc<IdentitySecret>,
    onion_sk: OnionSecret,
    relay_graph: Arc<RwLock<RelayGraph>>,
    incoming: Arc<ConcurrentQueue<(Bytes, Fingerprint)>>,
    degarblers: Cache<u64, ReplyDegarbler>,
    anon_destinations: Arc<RwLock<ReplyBlockStore>>,
    anon_identities: Arc<RwLock<AnonIdentities>>,
}
