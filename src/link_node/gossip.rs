use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use bytes::Bytes;
use earendil_crypt::RelayFingerprint;
use earendil_topology::AdjacencyDescriptor;
use itertools::Itertools;

use rand::seq::SliceRandom;
use rand::thread_rng;

use crate::link_node::link_protocol::LinkClient;

use super::{link::Link, LinkNodeCtx, NeighborIdSecret};

#[tracing::instrument(skip_all)]
pub async fn gossip_once(
    ctx: &LinkNodeCtx,
    link: &Link,
    remote_fp: Option<RelayFingerprint>,
) -> anyhow::Result<()> {
    if let Some(remote_fp) = remote_fp {
        fetch_identity(ctx, link, remote_fp).await?;
        sign_adjacency(ctx, link, remote_fp).await?;
    }
    gossip_graph(ctx, link).await?;

    Ok(())
}

// Step 1: Fetch the identity of the neighbor.
#[tracing::instrument(skip_all)]
async fn fetch_identity(
    ctx: &LinkNodeCtx,
    link: &Link,
    remote_fp: RelayFingerprint,
) -> anyhow::Result<()> {
    tracing::trace!("fetching identity from link neighbor");
    let their_id = LinkClient(link.rpc_transport())
        .identity(remote_fp)
        .await?
        .context("relay neighbors should give us their own id!!!")?;
    tracing::trace!(
        "got identity with fingerprint: {:?}\n and exit: {:?}",
        their_id.identity_pk.fingerprint(),
        their_id.exit_info,
    );

    ctx.relay_graph.write().insert_identity(their_id.clone())?;
    Ok(())
}

// Step 2: Sign an adjacency descriptor with the neighbor if the local node is "left" of the neighbor.
#[tracing::instrument(skip_all)]
async fn sign_adjacency(
    ctx: &LinkNodeCtx,
    link: &Link,
    remote_fp: RelayFingerprint,
) -> anyhow::Result<()> {
    if let NeighborIdSecret::Relay(my_sk) = ctx.my_id {
        // tracing::trace!("signing adjacency...");
        let my_fp = my_sk.public().fingerprint();
        if my_fp < remote_fp {
            // tracing::trace!("signing adjacency with {remote_fp}");
            let mut left_incomplete = AdjacencyDescriptor {
                left: my_fp,
                right: remote_fp,
                left_sig: Bytes::new(),
                right_sig: Bytes::new(),
                unix_timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            };
            left_incomplete.left_sig = my_sk.sign(left_incomplete.to_sign().as_bytes());
            let complete = LinkClient(link.rpc_transport())
                .sign_adjacency(left_incomplete)
                .await?
                .context("remote refused to sign off")?;
            ctx.relay_graph.write().insert_adjacency(complete.clone())?;
        }
    } else {
        tracing::trace!("skipping signing adjacency...");
    }
    Ok(())
}

// Step 3: Gossip the relay graph, by asking info about random nodes.
#[tracing::instrument(skip_all)]
async fn gossip_graph(ctx: &LinkNodeCtx, link: &Link) -> anyhow::Result<()> {
    tracing::trace!("gossiping relay graph with exit: {:?}", ctx.cfg.exit_info);

    let all_known_nodes = ctx.relay_graph.read().all_nodes().collect_vec();
    let random_sample = all_known_nodes
        .choose_multiple(&mut thread_rng(), 10.min(all_known_nodes.len()))
        .copied()
        .collect_vec();
    let adjacencies = LinkClient(link.rpc_transport())
        .adjacencies(random_sample.clone())
        .await?;

    for adjacency in adjacencies {
        let left_fp = adjacency.left;
        let right_fp = adjacency.right;

        let ourselves = ctx.cfg.relay_config.clone();
        let left_id = if ourselves.is_some()
            && ourselves.as_ref().unwrap().0.public().fingerprint() == left_fp
        {
            None
        } else {
            LinkClient(link.rpc_transport()).identity(left_fp).await?
        };

        let right_id =
            if ourselves.is_some() && ourselves.unwrap().0.public().fingerprint() == right_fp {
                None
            } else {
                LinkClient(link.rpc_transport()).identity(right_fp).await?
            };

        // fetch and insert the identities. we unconditionally do this since identity descriptors may change over time
        if let Some(left_id) = left_id {
            ctx.relay_graph.write().insert_identity(left_id)?
        }

        if let Some(right_id) = right_id {
            ctx.relay_graph.write().insert_identity(right_id)?
        }

        // insert the adjacency
        ctx.relay_graph.write().insert_adjacency(adjacency)?
    }

    Ok(())
}

#[cfg(test)]
mod tests {

    use bytes::Bytes;
    use earendil_crypt::{HavenEndpoint, HavenFingerprint, RelayIdentitySecret};
    use earendil_packet::crypt::DhSecret;
    use earendil_topology::{ExitConfig, ExitInfo, IdentityDescriptor};

    #[test]
    fn test_identity_descriptor_sign_and_verify() {
        // Create a mock RelayIdentitySecret
        let my_identity = RelayIdentitySecret::generate();

        // Create a mock DhSecret
        let my_onion = DhSecret::generate();

        let exit_info = Some(ExitInfo {
            haven_endpoint: HavenEndpoint {
                fingerprint: HavenFingerprint::from_bytes(&[0u8; 20]),
                port: 8080,
            },
            config: ExitConfig {
                allowed_ports: vec![80, 443],
            },
        });

        // Create a new IdentityDescriptor
        let descriptor = IdentityDescriptor::new(&my_identity, &my_onion, exit_info);

        // Verify the descriptor
        assert!(descriptor.verify().is_ok(), "Verification should succeed");

        // Test with invalid signature
        let mut invalid_descriptor = descriptor.clone();
        invalid_descriptor.sig = Bytes::from(vec![0u8; 64]); // Replace with an invalid signature
        assert!(
            invalid_descriptor.verify().is_err(),
            "Verification should fail with invalid signature"
        );

        // Test with modified data
        let mut modified_descriptor = descriptor.clone();
        modified_descriptor.unix_timestamp += 1; // Modify the timestamp
        assert!(
            modified_descriptor.verify().is_err(),
            "Verification should fail with modified data"
        );

        // Test with different exit_info
        let different_exit_info = Some(ExitInfo {
            haven_endpoint: HavenEndpoint {
                fingerprint: HavenFingerprint::from_bytes(&[1u8; 20]),
                port: 9090,
            },
            config: ExitConfig {
                allowed_ports: vec![8080],
            },
        });
        let different_descriptor =
            IdentityDescriptor::new(&my_identity, &my_onion, different_exit_info);
        assert!(
            different_descriptor.verify().is_ok(),
            "Verification should succeed with different exit_info"
        );
        assert_ne!(
            descriptor, different_descriptor,
            "Descriptors with different exit_info should not be equal"
        );
    }
}
