use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use bytes::Bytes;
use earendil_topology::{AdjacencyDescriptor, IdentityDescriptor};
use rand::Rng;

use super::{connection::Connection, DaemonContext};

/// Loop that gossips things around
pub async fn gossip_loop(ctx: DaemonContext) -> anyhow::Result<()> {
    // set up the topology stuff for myself
    ctx.relay_graph
        .write()
        .insert_identity(IdentityDescriptor::new(&ctx.identity, &ctx.onion_sk));
    let mut timer = smol::Timer::interval(Duration::from_secs(1));
    loop {
        (&mut timer).await;
        let neighs = ctx.table.all_neighs();
        if neighs.is_empty() {
            log::debug!("skipping gossip due to no neighs");
            continue;
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
    }
}

async fn gossip_once(ctx: &DaemonContext, conn: &Connection) -> anyhow::Result<()> {
    let remote_idpk = conn.remote_idpk();
    let remote_fingerprint = remote_idpk.fingerprint();
    log::debug!(
        "gossiping with random neighbor {}",
        remote_idpk.fingerprint()
    );
    // get their identity if we don't have if
    if ctx
        .relay_graph
        .read()
        .identity(&remote_fingerprint)
        .is_none()
    {
        log::debug!("getting identity of {remote_fingerprint}");
        let their_id = conn
            .n2n_rpc()
            .identity(remote_fingerprint)
            .await?
            .context("they refused to give us their id descriptor")?;
        if !ctx.relay_graph.write().insert_identity(their_id) {
            anyhow::bail!("could not accept their identity")
        }
    }
    // sign an adjacency if we are left of them
    if ctx.identity.public().fingerprint() < remote_idpk.fingerprint() {
        log::debug!("signing adjacency with {remote_fingerprint}");
        let mut left_incomplete = AdjacencyDescriptor {
            left: ctx.identity.public().fingerprint(),
            right: remote_fingerprint,
            left_sig: Bytes::new(),
            right_sig: Bytes::new(),
            unix_timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        };
        left_incomplete.left_sig = ctx.identity.sign(left_incomplete.to_sign().as_bytes());
        let complete = conn
            .n2n_rpc()
            .sign_adjacency(left_incomplete)
            .await?
            .context("remote refused to sign off")?;
        ctx.relay_graph.write().insert_adjacency(complete)?;
    }
    Ok(())
}
