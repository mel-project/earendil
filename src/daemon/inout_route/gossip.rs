use anyhow::Context;
use earendil_crypt::RelayFingerprint;

use crate::{
    context::{DaemonContext, RELAY_GRAPH},
    daemon::{inout_route::link_protocol::LinkClient, link::Link},
};

pub async fn gossip_once(
    ctx: &DaemonContext,
    link: &Link,
    remote_fp: Option<RelayFingerprint>,
) -> anyhow::Result<()> {
    if let Some(remote_fp) = remote_fp {
        fetch_identity(ctx, link, remote_fp).await?;
        sign_adjacency(ctx, link).await?;
    }
    gossip_graph(ctx, link).await?;

    Ok(())
}

// Step 1: Fetch the identity of the neighbor.
#[tracing::instrument(skip_all)]
async fn fetch_identity(
    ctx: &DaemonContext,
    link: &Link,
    remote_fp: RelayFingerprint,
) -> anyhow::Result<()> {
    tracing::debug!("fetching identity...");
    let their_id = LinkClient(link.rpc_transport())
        .identity(remote_fp)
        .await?
        .context("relay neighbors should give us their own id!!!")?;
    ctx.get(RELAY_GRAPH).write().insert_identity(their_id)?;
    Ok(())
}

// Step 2: Sign an adjacency descriptor with the neighbor if the local node is "left" of the neighbor.
#[tracing::instrument(skip_all)]
async fn sign_adjacency(ctx: &DaemonContext, link_client: &Link) -> anyhow::Result<()> {
    let neighbor_fp = match &lctx.neighbor {
        Either::Left(RelayNeighbor(_, fp)) => fp,
        Either::Right(_) => return Ok(()),
    };
    tracing::debug!("signing adjacency...");
    let my_sk = lctx
        .ctx
        .get(MY_RELAY_IDENTITY)
        .expect("only relays have global identities");
    let my_fingerprint = my_sk.public().fingerprint();
    if my_fingerprint < *neighbor_fp {
        // tracing::debug!("signing adjacency with {remote_fingerprint}");
        let mut left_incomplete = AdjacencyDescriptor {
            left: my_fingerprint,
            right: *neighbor_fp,
            left_sig: Bytes::new(),
            right_sig: Bytes::new(),
            unix_timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        };
        left_incomplete.left_sig = my_sk.sign(left_incomplete.to_sign().as_bytes());
        let complete = link_client
            .sign_adjacency(left_incomplete)
            .await?
            .context("remote refused to sign off")?;
        lctx.ctx
            .get(RELAY_GRAPH)
            .write()
            .insert_adjacency(complete.clone())?;
        // tracing::trace!("inserted the new adjacency {:?} into the graph", complete);
    }
    Ok(())
}

// Step 3: Gossip the relay graph, by asking info about random nodes.
#[tracing::instrument(skip_all)]
async fn gossip_graph(ctx: &DaemonContext, link_client: &Link) -> anyhow::Result<()> {
    tracing::debug!("gossipping relay graph...");
    let all_known_nodes = lctx.ctx.get(RELAY_GRAPH).read().all_nodes().collect_vec();
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

        let left_id = if let Some(val) = lctx.ctx.get(IDENTITY_CACHE).get(&left_fp) {
            Some(val)
        } else {
            link_client
                .identity(left_fp)
                .await?
                .tap_some(|id| lctx.ctx.get(IDENTITY_CACHE).insert(left_fp, id.clone()))
        };

        let right_id = if let Some(val) = lctx.ctx.get(IDENTITY_CACHE).get(&right_fp) {
            Some(val)
        } else {
            link_client
                .identity(right_fp)
                .await?
                .tap_some(|id| lctx.ctx.get(IDENTITY_CACHE).insert(right_fp, id.clone()))
        };

        // fetch and insert the identities. we unconditionally do this since identity descriptors may change over time
        if let Some(left_id) = left_id {
            lctx.ctx.get(RELAY_GRAPH).write().insert_identity(left_id)?
        }

        if let Some(right_id) = right_id {
            lctx.ctx
                .get(RELAY_GRAPH)
                .write()
                .insert_identity(right_id)?
        }

        // insert the adjacency
        lctx.ctx
            .get(RELAY_GRAPH)
            .write()
            .insert_adjacency(adjacency)?
    }
    Ok(())
}
