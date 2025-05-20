use async_stdcode::{StdcodeReader, StdcodeWriter};
use bytes::Bytes;
use earendil_crypt::RelayIdentityPublic;
use futures_util::AsyncReadExt;
use haiyuu::{Handle, Process};
use nursery_macro::nursery;
use picomux::{PicoMux, Stream};
use sillad::listener::{Listener, ListenerExt};
use std::{
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    InLinkConfig, NodeAddr, NodeIdentity, ObfsConfig, auth::AddrAssignment, link::Link,
    link_table::LinkTable, router::Router, topology::Topology,
};

/// Main function to start a listener for incoming links
pub async fn in_link(
    topo: Topology,
    cfg: InLinkConfig,
    table: Arc<RwLock<LinkTable>>,
    router: Handle<Router>,
) -> anyhow::Result<()> {
    let mut listener = match &cfg.obfs {
        ObfsConfig::None => sillad::tcp::TcpListener::bind(cfg.listen).await?.dynamic(),
        ObfsConfig::Sosistab3(cookie) => {
            let cookie = sillad_sosistab3::Cookie::new(cookie);
            sillad_sosistab3::listener::SosistabListener::new(
                sillad::tcp::TcpListener::bind(cfg.listen).await?,
                cookie,
            )
            .dynamic()
        }
    };

    tracing::info!(
        listen = display(&cfg.listen),
        obfs = debug(&cfg.obfs),
        "in_link listening"
    );

    nursery!({
        loop {
            let conn = listener.accept().await?;
            let topo = topo.clone();
            let table = table.clone();
            let router = router.clone();
            // Spawn a task to handle this connection
            spawn!(async move {
                if let Err(e) = handle_connection(topo, conn, table, router).await {
                    tracing::warn!(err = debug(e), "in_link connection handler failed");
                }
            })
            .detach();
        }
    })
}

/// Handles a single incoming connection
async fn handle_connection(
    topo: Topology,
    conn: Box<dyn sillad::Pipe>,
    table: Arc<RwLock<LinkTable>>,
    router: Handle<Router>,
) -> anyhow::Result<()> {
    // Split the connection and set up picomux
    let (read, write) = conn.split();
    let mux = PicoMux::new(read, write);

    // Handle authentication first
    let auth_stream = mux.accept().await?;
    if auth_stream.metadata() != b"auth" {
        anyhow::bail!("first stream not auth")
    }
    let (neigh_addr, local_addr) = in_link_auth(topo.identity(), auth_stream).await?;

    // Create and register the link
    let link_stream = mux.accept().await?;
    if link_stream.metadata() != b"link" {
        anyhow::bail!("second stream not link")
    }
    let gossip_stream = mux.accept().await?;
    if gossip_stream.metadata() != b"gossip" {
        anyhow::bail!("third stream not link")
    }

    let link_id = LinkTable::next_id();

    let on_drop = {
        let table = table.clone();
        move || {
            table.write().unwrap().remove(link_id);
        }
    };

    let link = Link {
        link_pipe: Box::new(link_stream),
        gossip_pipe: Box::new(gossip_stream),
        router: router.downgrade(),
        topo,
        on_drop: Box::new(on_drop),
        neigh_addr,
    }
    .spawn_smolscale();

    // Insert the link into the table
    table
        .write()
        .unwrap()
        .insert(local_addr, neigh_addr, link_id, link);

    Ok(())
}

/// Handles the authentication phase of an incoming link
async fn in_link_auth(secret: NodeIdentity, auth: Stream) -> anyhow::Result<(NodeAddr, NodeAddr)> {
    let (down, up) = auth.split();
    let mut down = StdcodeReader::new(down);
    let mut up = StdcodeWriter::new(up);
    // send our challenge
    let challenge: [u8; 32] = rand::random();
    up.write(challenge).await?;

    // Read the peer's identity
    let peer_id: u128 = down.read().await?;

    let (neigh_addr, local_addr) = match secret {
        NodeIdentity::Relay(relay_secret) => {
            if peer_id == 0 {
                // Peer is a relay
                let peer_key: RelayIdentityPublic = down.read().await?;
                let challenge_sig: Bytes = down.read().await?;
                let signed_val =
                    blake3::keyed_hash(b"linkauth________________________", &challenge);
                if peer_key
                    .verify(signed_val.as_bytes(), &challenge_sig)
                    .is_err()
                {
                    up.write(Some("challenge verification failed")).await?;
                    anyhow::bail!("challenge failed")
                }

                // For relay-to-relay links
                up.write::<Option<String>>(None).await?; // No error

                // Send address assignment
                let assignment = AddrAssignment {
                    client_id: 0, // Relays always use client_id 0
                    unix_secs: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                };
                up.write(&assignment).await?;

                // Return the neighbor address and our local address
                (
                    NodeAddr {
                        relay: peer_key.fingerprint(),
                        client_id: 0,
                    },
                    NodeAddr {
                        relay: relay_secret.public().fingerprint(),
                        client_id: 0,
                    },
                )
            } else {
                // Peer is a client, we assign an ID with a consistent algo. Currently we don't handle collisions yet, this should change
                let client_id = u64::from_be_bytes(
                    blake3::hash(format!("{:?}--{}", secret, peer_id).as_bytes()).as_bytes()[..8]
                        .try_into()
                        .unwrap(),
                );

                up.write::<Option<String>>(None).await?; // No error

                // Send address assignment
                let assignment = AddrAssignment {
                    client_id,
                    unix_secs: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or(Duration::ZERO)
                        .as_secs(),
                };
                up.write(&assignment).await?;

                // Return the neighbor address and our local address
                (
                    NodeAddr {
                        relay: relay_secret.public().fingerprint(),
                        client_id,
                    },
                    NodeAddr {
                        relay: relay_secret.public().fingerprint(),
                        client_id: 0,
                    },
                )
            }
        }
        NodeIdentity::ClientBearer(_) => {
            // Clients typically don't accept incoming connections
            anyhow::bail!("Clients cannot accept incoming connections")
        }
    };

    Ok((neigh_addr, local_addr))
}
