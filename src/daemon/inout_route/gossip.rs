use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use bytes::Bytes;
use earendil_crypt::{ClientId, RelayFingerprint, RelayIdentityPublic};
use earendil_topology::{AdjacencyDescriptor, IdentityDescriptor};
use itertools::Itertools;
use moka::sync::{Cache, CacheBuilder};
use rand::{seq::SliceRandom, thread_rng, Rng};
use smol_timeout::TimeoutExt;
use tap::TapOptional;

use crate::daemon::context::{CtxField, GLOBAL_IDENTITY, RELAY_GRAPH};

use super::{link_protocol::LinkClient, DaemonContext};

pub static STARTUP_TIME: CtxField<Instant> = |_| Instant::now();

/// Loop for gossipping with a relay
#[tracing::instrument(skip(ctx, neighbor_idpk, link_client))]
pub async fn client_gossip_with_relay_loop(
    ctx: DaemonContext,
    neighbor_idpk: RelayIdentityPublic,
    link_client: LinkClient,
) -> anyhow::Result<()> {
    scopeguard::defer!(tracing::info!(
        "gossip loop for {} stopped",
        neighbor_idpk.fingerprint()
    ));
    loop {
        let once = async {
            if let Err(err) = client_gossip_once_with_relay(&ctx, neighbor_idpk, &link_client).await
            {
                tracing::warn!(
                    "gossip with {} failed: {:?}",
                    neighbor_idpk.fingerprint(),
                    err
                );
            }
        };
        // pin_mut!(once);
        if once.timeout(Duration::from_secs(10)).await.is_none() {
            tracing::warn!("gossip once timed out");
        };
        smol::Timer::after(gossip_interval(ctx.get(STARTUP_TIME))).await;
    }
}

/// Loop for gossipping with a relay
#[tracing::instrument(skip(ctx, neighbor_idpk, link_client))]
pub async fn relay_gossip_with_relay_loop(
    ctx: DaemonContext,
    neighbor_idpk: RelayIdentityPublic,
    link_client: LinkClient,
) -> anyhow::Result<()> {
    scopeguard::defer!(tracing::info!(
        "gossip loop for {} stopped",
        neighbor_idpk.fingerprint()
    ));
    loop {
        let once = async {
            if let Err(err) = relay_gossip_once_with_relay(&ctx, neighbor_idpk, &link_client).await
            {
                tracing::warn!(
                    "gossip with {} failed: {:?}",
                    neighbor_idpk.fingerprint(),
                    err
                );
            }
        };
        // pin_mut!(once);
        if once.timeout(Duration::from_secs(10)).await.is_none() {
            tracing::warn!("gossip once timed out");
        };
        smol::Timer::after(gossip_interval(ctx.get(STARTUP_TIME))).await;
    }
}

/// One round of gossip with a particular neighbor.
#[tracing::instrument(skip(ctx, neighbor_idpk, link_client))]
async fn client_gossip_once_with_relay(
    ctx: &DaemonContext,
    neighbor_idpk: RelayIdentityPublic,
    link_client: &LinkClient,
) -> anyhow::Result<()> {
    // tracing::trace!("gossip_once to {}", neighbor_idpk.fingerprint());
    fetch_identity(ctx, &neighbor_idpk, link_client).await?;
    gossip_graph_with_relay(ctx, link_client).await?;
    Ok(())
}

/// One round of gossip with a particular neighbor.
#[tracing::instrument(skip(ctx, neighbor_idpk, link_client))]
async fn relay_gossip_once_with_relay(
    ctx: &DaemonContext,
    neighbor_idpk: RelayIdentityPublic,
    link_client: &LinkClient,
) -> anyhow::Result<()> {
    // tracing::trace!("gossip_once to {}", neighbor_idpk.fingerprint());
    fetch_identity(ctx, &neighbor_idpk, link_client).await?;
    sign_adjacency(ctx, &neighbor_idpk, link_client).await?;
    gossip_graph_with_relay(ctx, link_client).await?;
    Ok(())
}

// Step 1: Fetch the identity of the neighbor.
#[tracing::instrument(skip(ctx, neighbor_idpk, link_client))]
async fn fetch_identity(
    ctx: &DaemonContext,
    neighbor_idpk: &RelayIdentityPublic,
    link_client: &LinkClient,
) -> anyhow::Result<()> {
    tracing::debug!("fetching identity...");
    let remote_fingerprint = neighbor_idpk.fingerprint();
    // tracing::debug!("getting identity of {remote_fingerprint}");

    let their_id = link_client
        .identity(remote_fingerprint)
        .await?
        .context("they refused to give us their id descriptor")?;
    ctx.get(RELAY_GRAPH).write().insert_identity(their_id)?;

    Ok(())
}

// Step 2: Sign an adjacency descriptor with the neighbor if the local node is "left" of the neighbor.
#[tracing::instrument(skip(ctx, neighbor_idpk, link_client))]
async fn sign_adjacency(
    ctx: &DaemonContext,
    neighbor_idpk: &RelayIdentityPublic,
    link_client: &LinkClient,
) -> anyhow::Result<()> {
    tracing::debug!("signing adjacency...");
    let remote_fingerprint = neighbor_idpk.fingerprint();
    let my_sk = ctx
        .get(GLOBAL_IDENTITY)
        .expect("only relays have global identities");
    let my_fingerprint = my_sk.public().fingerprint();
    if my_fingerprint < remote_fingerprint {
        // tracing::debug!("signing adjacency with {remote_fingerprint}");
        let mut left_incomplete = AdjacencyDescriptor {
            left: my_fingerprint,
            right: remote_fingerprint,
            left_sig: Bytes::new(),
            right_sig: Bytes::new(),
            unix_timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        };
        left_incomplete.left_sig = my_sk.sign(left_incomplete.to_sign().as_bytes());
        let complete = link_client
            .sign_adjacency(left_incomplete)
            .await?
            .context("remote refused to sign off")?;
        ctx.get(RELAY_GRAPH)
            .write()
            .insert_adjacency(complete.clone())?;
        // tracing::trace!("inserted the new adjacency {:?} into the graph", complete);
    }
    Ok(())
}

// Step 3: Gossip the relay graph, by asking info about random nodes.
#[tracing::instrument(skip(ctx, link_client))]
async fn gossip_graph_with_relay(
    ctx: &DaemonContext,
    link_client: &LinkClient,
) -> anyhow::Result<()> {
    tracing::debug!("gossipping relay graph...");
    let all_known_nodes = ctx.get(RELAY_GRAPH).read().all_nodes().collect_vec();
    let random_sample = all_known_nodes
        .choose_multiple(&mut thread_rng(), 10.min(all_known_nodes.len()))
        .copied()
        .collect_vec();
    let adjacencies = link_client.adjacencies(random_sample).await?;
    for adjacency in adjacencies {
        let left_fp = adjacency.left;
        let right_fp = adjacency.right;

        static IDENTITY_CACHE: CtxField<Cache<RelayFingerprint, IdentityDescriptor>> = |_| {
            CacheBuilder::default()
                .time_to_live(Duration::from_secs(60))
                .build()
        };

        let left_id = if let Some(val) = ctx.get(IDENTITY_CACHE).get(&left_fp) {
            Some(val)
        } else {
            link_client
                .identity(left_fp)
                .await?
                .tap_some(|id| ctx.get(IDENTITY_CACHE).insert(left_fp, id.clone()))
        };

        let right_id = if let Some(val) = ctx.get(IDENTITY_CACHE).get(&right_fp) {
            Some(val)
        } else {
            link_client
                .identity(right_fp)
                .await?
                .tap_some(|id| ctx.get(IDENTITY_CACHE).insert(right_fp, id.clone()))
        };

        // fetch and insert the identities. we unconditionally do this since identity descriptors may change over time
        if let Some(left_id) = left_id {
            ctx.get(RELAY_GRAPH).write().insert_identity(left_id)?
        }

        if let Some(right_id) = right_id {
            ctx.get(RELAY_GRAPH).write().insert_identity(right_id)?
        }

        // insert the adjacency
        ctx.get(RELAY_GRAPH).write().insert_adjacency(adjacency)?
    }
    Ok(())
}

fn gossip_interval(start_time: &Instant) -> Duration {
    let elapsed_secs = start_time.elapsed().as_secs_f64();
    // logistic function that stabilizes to ~10-sec at ~70 secs
    let interval_secs = 10. / (1. + 50. * (-0.15 * elapsed_secs).exp());
    let mut rng = rand::thread_rng();
    let with_jitter = rng.gen_range(interval_secs..(interval_secs * 2.));

    Duration::from_secs_f64(with_jitter)
}

/// Loop for gossipping with a client
#[tracing::instrument(skip(ctx, client_id, link_client))]
pub async fn gossip_with_client_loop(
    ctx: DaemonContext,
    client_id: ClientId,
    link_client: LinkClient,
) -> anyhow::Result<()> {
    scopeguard::defer!(tracing::info!(
        "gossip loop for client {} stopped",
        client_id
    ));
    loop {
        let once = async {
            if let Err(err) = gossip_once_with_client(&ctx, &link_client).await {
                tracing::warn!("gossip with client {} failed: {:?}", client_id, err);
            }
        };

        if once.timeout(Duration::from_secs(10)).await.is_none() {
            tracing::warn!("gossip once timed out");
        };
        smol::Timer::after(gossip_interval(ctx.get(STARTUP_TIME))).await;
    }
}

/// One round of gossip with a particular neighbor.
#[tracing::instrument(skip(ctx, link_client))]
async fn gossip_once_with_client(
    ctx: &DaemonContext,
    link_client: &LinkClient,
) -> anyhow::Result<()> {
    gossip_graph_with_client(ctx, link_client).await?;
    Ok(())
}

// Step 3: Gossip the relay graph, by asking info about random nodes.
#[tracing::instrument(skip(ctx, link_client))]
async fn gossip_graph_with_client(
    ctx: &DaemonContext,
    link_client: &LinkClient,
) -> anyhow::Result<()> {
    let all_known_nodes = ctx.get(RELAY_GRAPH).read().all_nodes().collect_vec();
    let random_sample = all_known_nodes
        .choose_multiple(&mut thread_rng(), 10.min(all_known_nodes.len()))
        .copied()
        .collect_vec();

    let adjacencies = link_client.adjacencies(random_sample).await?;
    for adjacency in adjacencies {
        let left_fp = adjacency.left;
        let right_fp = adjacency.right;

        static IDENTITY_CACHE: CtxField<Cache<RelayFingerprint, IdentityDescriptor>> = |_| {
            CacheBuilder::default()
                .time_to_live(Duration::from_secs(60))
                .build()
        };

        let left_id = if let Some(val) = ctx.get(IDENTITY_CACHE).get(&left_fp) {
            Some(val)
        } else {
            link_client
                .identity(left_fp)
                .await?
                .tap_some(|id| ctx.get(IDENTITY_CACHE).insert(left_fp, id.clone()))
        };

        let right_id = if let Some(val) = ctx.get(IDENTITY_CACHE).get(&right_fp) {
            Some(val)
        } else {
            link_client
                .identity(right_fp)
                .await?
                .tap_some(|id| ctx.get(IDENTITY_CACHE).insert(right_fp, id.clone()))
        };

        // fetch and insert the identities. we unconditionally do this since identity descriptors may change over time
        if let Some(left_id) = left_id {
            ctx.get(RELAY_GRAPH).write().insert_identity(left_id)?
        }

        if let Some(right_id) = right_id {
            ctx.get(RELAY_GRAPH).write().insert_identity(right_id)?
        }

        // insert the adjacency
        ctx.get(RELAY_GRAPH).write().insert_adjacency(adjacency)?
    }
    Ok(())
}
