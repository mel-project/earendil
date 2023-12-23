use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use bytes::Bytes;
use earendil_topology::{AdjacencyDescriptor, IdentityDescriptor};
use itertools::Itertools;
use rand::{seq::SliceRandom, thread_rng, Rng};
use smol_timeout::TimeoutExt;
use smolscale::reaper::TaskReaper;

use super::{
    context::{GLOBAL_IDENTITY, GLOBAL_ONION_SK, NEIGH_TABLE, RELAY_GRAPH},
    link_connection::LinkConnection,
    DaemonContext,
};

/// Loop that gossips things around
pub async fn gossip_loop(ctx: DaemonContext) -> anyhow::Result<()> {
    let mut sleep_timer = smol::Timer::interval(Duration::from_secs(1));
    let reaper = TaskReaper::new();
    loop {
        (&mut sleep_timer).await;
        // first insert ourselves
        let am_i_relay = !ctx.init().in_routes.is_empty();
        ctx.get(RELAY_GRAPH)
            .write()
            .insert_identity(IdentityDescriptor::new(
                ctx.get(GLOBAL_IDENTITY),
                ctx.get(GLOBAL_ONION_SK),
                am_i_relay,
            ))?;
        let neighs = ctx.get(NEIGH_TABLE).all_neighs();
        if neighs.is_empty() {
            log::debug!("skipping gossip due to no neighs");
            continue;
        }
        // pick a random neighbor and do sync stuff.
        // we spawn a new task to prevent head-of-line blocking stuff
        let rand_neigh = neighs[rand::thread_rng().gen_range(0..neighs.len())].clone();
        let ctx = ctx.clone();
        reaper.attach(smolscale::spawn(async move {
            let once = async {
                if let Err(err) = gossip_once(&ctx, &rand_neigh).await {
                    log::warn!(
                        "gossip with {} failed: {:?}",
                        rand_neigh.remote_idpk().fingerprint(),
                        err
                    );
                }
            };
            // pin_mut!(once);
            if once.timeout(Duration::from_secs(60)).await.is_none() {
                log::warn!(
                    "gossip once with {} timed out",
                    rand_neigh.remote_idpk().fingerprint()
                );
            };
        }));
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
    ctx.get(RELAY_GRAPH).write().insert_identity(their_id)?;

    Ok(())
}

// Step 2: Sign an adjacency descriptor with the neighbor if the local node is "left" of the neighbor.
async fn sign_adjacency(ctx: &DaemonContext, conn: &LinkConnection) -> anyhow::Result<()> {
    let remote_idpk = conn.remote_idpk();
    let remote_fingerprint = remote_idpk.fingerprint();
    if ctx.get(GLOBAL_IDENTITY).public().fingerprint() < remote_idpk.fingerprint() {
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
        let complete = conn
            .link_rpc()
            .sign_adjacency(left_incomplete)
            .await?
            .context("remote refused to sign off")?;
        ctx.get(RELAY_GRAPH).write().insert_adjacency(complete)?;
    }
    Ok(())
}

// Step 3: Gossip the relay graph, by asking info about random nodes.
async fn gossip_graph(ctx: &DaemonContext, conn: &LinkConnection) -> anyhow::Result<()> {
    // let remote_fingerprint = conn.remote_idpk().fingerprint();
    let all_known_nodes = ctx.get(RELAY_GRAPH).read().all_nodes().collect_vec();
    let random_sample = all_known_nodes
        .choose_multiple(&mut thread_rng(), 10.min(all_known_nodes.len()))
        .copied()
        .collect_vec();
    // log::debug!(
    //     "asking {remote_fingerprint} for neighbors of {} neighbors!",
    //     random_sample.len()
    // );
    let adjacencies = conn.link_rpc().adjacencies(random_sample).await?;
    for adjacency in adjacencies {
        let left_fp = adjacency.left;
        let right_fp = adjacency.right;
        // fetch and insert the identities. we unconditionally do this since identity descriptors may change over time
        if let Some(left_id) = conn.link_rpc().identity(left_fp).await? {
            ctx.get(RELAY_GRAPH).write().insert_identity(left_id)?
        }

        if let Some(right_id) = conn.link_rpc().identity(right_fp).await? {
            ctx.get(RELAY_GRAPH).write().insert_identity(right_id)?
        }

        // insert the adjacency
        ctx.get(RELAY_GRAPH).write().insert_adjacency(adjacency)?
    }
    Ok(())
}
