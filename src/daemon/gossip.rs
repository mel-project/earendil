use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use bytes::Bytes;
use earendil_topology::{AdjacencyDescriptor, IdentityDescriptor};
use futures_util::{future::select, pin_mut};
use itertools::Itertools;
use moro::async_scope;
use rand::{seq::SliceRandom, thread_rng, Rng};

use super::{link_connection::LinkConnection, DaemonContext};

/// Loop that gossips things around
pub async fn gossip_loop(ctx: DaemonContext) -> anyhow::Result<()> {
    // set up the topology stuff for myself
    ctx.relay_graph
        .write()
        .insert_identity(IdentityDescriptor::new(&ctx.identity, &ctx.onion_sk))?;
    let mut timer = smol::Timer::interval(Duration::from_secs(5));
    loop {
        let once = async {
            let neighs = ctx.table.all_neighs();
            if neighs.is_empty() {
                log::debug!("skipping gossip due to no neighs");
            }
            // pick a random neighbor and do sync stuff
            let rand_neigh = &neighs[rand::thread_rng().gen_range(0..neighs.len())];

            if let Err(err) = gossip_once(&ctx, rand_neigh).await {
                log::warn!(
                    "gossip with {} failed: {:?}",
                    rand_neigh.remote_idpk().fingerprint(),
                    err
                );
            }
        };
        pin_mut!(once);
        select(&mut timer, once).await;
    }
}

/// One round of gossip with a particular neighbor.
async fn gossip_once(ctx: &DaemonContext, conn: &LinkConnection) -> anyhow::Result<()> {
    fetch_identity(ctx, conn).await?;
    sign_adjacency(ctx, conn).await?;
    gossip_graph(ctx, conn).await?;
    Ok(())
}

// Step 1: Fetch the identity of the neighbor.
async fn fetch_identity(ctx: &DaemonContext, conn: &LinkConnection) -> anyhow::Result<()> {
    let remote_fingerprint = conn.remote_idpk().fingerprint();

    log::trace!("getting identity of {remote_fingerprint}");
    let their_id = conn
        .link_rpc()
        .identity(remote_fingerprint)
        .await?
        .context("they refused to give us their id descriptor")?;
    ctx.relay_graph.write().insert_identity(their_id)?;

    Ok(())
}

// Step 2: Sign an adjacency descriptor with the neighbor if the local node is "left" of the neighbor.
async fn sign_adjacency(ctx: &DaemonContext, conn: &LinkConnection) -> anyhow::Result<()> {
    let remote_idpk = conn.remote_idpk();
    let remote_fingerprint = remote_idpk.fingerprint();
    if ctx.identity.public().fingerprint() < remote_idpk.fingerprint() {
        log::trace!("signing adjacency with {remote_fingerprint}");
        let mut left_incomplete = AdjacencyDescriptor {
            left: ctx.identity.public().fingerprint(),
            right: remote_fingerprint,
            left_sig: Bytes::new(),
            right_sig: Bytes::new(),
            unix_timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        };
        left_incomplete.left_sig = ctx.identity.sign(left_incomplete.to_sign().as_bytes());
        let complete = conn
            .link_rpc()
            .sign_adjacency(left_incomplete)
            .await?
            .context("remote refused to sign off")?;
        ctx.relay_graph.write().insert_adjacency(complete)?;
    }
    Ok(())
}

// Step 3: Gossip the relay graph, by asking info about random nodes.
async fn gossip_graph(ctx: &DaemonContext, conn: &LinkConnection) -> anyhow::Result<()> {
    let remote_fingerprint = conn.remote_idpk().fingerprint();
    let all_known_nodes = ctx.relay_graph.read().all_nodes().collect_vec();
    let random_sample = all_known_nodes
        .choose_multiple(&mut thread_rng(), 10.min(all_known_nodes.len()))
        .copied()
        .collect_vec();
    log::debug!(
        "asking {remote_fingerprint} for neighbors of {:?}!",
        random_sample
    );
    let adjacencies = conn.link_rpc().adjacencies(random_sample).await?;
    for adjacency in adjacencies {
        let left_fp = adjacency.left;
        let right_fp = adjacency.right;
        // insert all unknown identities
        if ctx.relay_graph.read().identity(&left_fp).is_none() {
            if let Some(left_id) = conn.link_rpc().identity(left_fp).await? {
                ctx.relay_graph.write().insert_identity(left_id)?
            }
        }
        if ctx.relay_graph.read().identity(&right_fp).is_none() {
            if let Some(right_id) = conn.link_rpc().identity(right_fp).await? {
                ctx.relay_graph.write().insert_identity(right_id)?
            }
        }
        // insert the adjacency
        ctx.relay_graph.write().insert_adjacency(adjacency)?
    }
    Ok(())
}
