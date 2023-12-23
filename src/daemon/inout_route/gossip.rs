use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use bytes::Bytes;
use earendil_crypt::IdentityPublic;
use earendil_topology::AdjacencyDescriptor;
use itertools::Itertools;
use rand::{seq::SliceRandom, thread_rng};
use smol_timeout::TimeoutExt;

use crate::daemon::context::{GLOBAL_IDENTITY, RELAY_GRAPH};

use super::{link_protocol::LinkClient, DaemonContext};

/// Loop that gossips things around
pub async fn gossip_loop(
    ctx: DaemonContext,
    neighbor_idpk: IdentityPublic,
    link_client: LinkClient,
) -> anyhow::Result<()> {
    let mut sleep_timer = smol::Timer::interval(Duration::from_secs(10));
    scopeguard::defer!(log::info!(
        "gossip loop for {} stopped",
        neighbor_idpk.fingerprint()
    ));
    loop {
        let once = async {
            if let Err(err) = gossip_once(&ctx, neighbor_idpk, &link_client).await {
                log::warn!(
                    "gossip with {} failed: {:?}",
                    neighbor_idpk.fingerprint(),
                    err
                );
            }
        };
        // pin_mut!(once);
        if once.timeout(Duration::from_secs(10)).await.is_none() {
            log::warn!("gossip once timed out");
        };
        log::debug!("GONNA SLEEP");
        (&mut sleep_timer).await;
    }
}

/// One round of gossip with a particular neighbor.
async fn gossip_once(
    ctx: &DaemonContext,
    neighbor_idpk: IdentityPublic,
    link_client: &LinkClient,
) -> anyhow::Result<()> {
    log::debug!("gossip_once to {}", neighbor_idpk.fingerprint());
    fetch_identity(ctx, &neighbor_idpk, link_client).await?;
    sign_adjacency(ctx, &neighbor_idpk, link_client).await?;
    gossip_graph(ctx, &neighbor_idpk, link_client).await?;
    Ok(())
}

// Step 1: Fetch the identity of the neighbor.
async fn fetch_identity(
    ctx: &DaemonContext,
    neighbor_idpk: &IdentityPublic,
    link_client: &LinkClient,
) -> anyhow::Result<()> {
    let remote_fingerprint = neighbor_idpk.fingerprint();
    log::trace!("getting identity of {remote_fingerprint}");

    let their_id = link_client
        .identity(remote_fingerprint)
        .await?
        .context("they refused to give us their id descriptor")?;
    ctx.get(RELAY_GRAPH).write().insert_identity(their_id)?;

    Ok(())
}

// Step 2: Sign an adjacency descriptor with the neighbor if the local node is "left" of the neighbor.
async fn sign_adjacency(
    ctx: &DaemonContext,
    neighbor_idpk: &IdentityPublic,
    link_client: &LinkClient,
) -> anyhow::Result<()> {
    let remote_fingerprint = neighbor_idpk.fingerprint();
    if ctx.get(GLOBAL_IDENTITY).public().fingerprint() < remote_fingerprint {
        log::trace!("signing adjacency with {remote_fingerprint}");
        let mut left_incomplete = AdjacencyDescriptor {
            left: ctx.get(GLOBAL_IDENTITY).public().fingerprint(),
            right: remote_fingerprint,
            left_sig: Bytes::new(),
            right_sig: Bytes::new(),
            unix_timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        };
        left_incomplete.left_sig = ctx
            .get(GLOBAL_IDENTITY)
            .sign(left_incomplete.to_sign().as_bytes());
        let complete = link_client
            .sign_adjacency(left_incomplete)
            .await?
            .context("remote refused to sign off")?;
        ctx.get(RELAY_GRAPH)
            .write()
            .insert_adjacency(complete.clone())?;
        log::trace!("inserted the new adjacency {:?} into the graph", complete);
    }
    Ok(())
}

// Step 3: Gossip the relay graph, by asking info about random nodes.
async fn gossip_graph(
    ctx: &DaemonContext,
    neighbor_idpk: &IdentityPublic,
    link_client: &LinkClient,
) -> anyhow::Result<()> {
    let remote_fingerprint = neighbor_idpk.fingerprint();
    let all_known_nodes = ctx.get(RELAY_GRAPH).read().all_nodes().collect_vec();
    log::info!("num known nodes: {}", all_known_nodes.len());
    let random_sample = all_known_nodes
        .choose_multiple(&mut thread_rng(), 10.min(all_known_nodes.len()))
        .copied()
        .collect_vec();
    log::debug!(
        "asking {remote_fingerprint} for neighbors of {} neighbors!",
        random_sample.len()
    );
    let adjacencies = link_client.adjacencies(random_sample).await?;
    for adjacency in adjacencies {
        let left_fp = adjacency.left;
        let right_fp = adjacency.right;
        // fetch and insert the identities. we unconditionally do this since identity descriptors may change over time
        if let Some(left_id) = link_client.identity(left_fp).await? {
            ctx.get(RELAY_GRAPH).write().insert_identity(left_id)?
        }

        if let Some(right_id) = link_client.identity(right_fp).await? {
            ctx.get(RELAY_GRAPH).write().insert_identity(right_id)?
        }

        // insert the adjacency
        ctx.get(RELAY_GRAPH).write().insert_adjacency(adjacency)?
    }
    Ok(())
}
