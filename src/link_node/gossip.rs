use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use earendil_crypt::{RelayFingerprint, RelayIdentitySecret};
use earendil_topology::{AdjacencyDescriptor, RelayGraph};
use haiyuu::WeakHandle;
use nanorpc::{JrpcRequest, JrpcResponse, RpcTransport};
use parking_lot::RwLock;
use rand::{seq::SliceRandom, Rng};

use crate::link_node::{link_protocol::LinkClient, switch_proc::SwitchMessage};

use super::{netgraph::NetGraph, switch_proc::SwitchProcess};

/// A loop to go around the graph and pull relay graph data from our relay neighbors.
pub async fn graph_gossip_loop(
    my_identity: Option<RelayIdentitySecret>,
    graph: NetGraph,
    switch: WeakHandle<SwitchProcess>,
) {
    loop {
        if let Err(err) = gossip_once(my_identity, graph.clone(), switch.clone()).await {
            tracing::warn!(err = debug(err), "failed to gossip once");
        }
        let graph_size = graph.read_graph(|g| g.size()) + 1;
        let sleep_secs =
            rand::thread_rng().gen_range((graph_size as f64)..2.0 * (graph_size as f64));
        tracing::debug!(graph_size, sleep_secs, "sleeping before gossipping again");
        smol::Timer::after(Duration::from_secs_f64(sleep_secs)).await;
    }
}

async fn gossip_once(
    my_identity: Option<RelayIdentitySecret>,
    graph: NetGraph,
    switch: WeakHandle<SwitchProcess>,
) -> anyhow::Result<()> {
    let (send, recv) = oneshot::channel();
    switch.send(SwitchMessage::DumpRelays(send)).await?;
    let relays = recv.await?;
    let neighbor_fp = relays
        .choose(&mut rand::thread_rng())
        .cloned()
        .context("no relay neighbors connected to the switch")?;
    let rpc = LinkClient(SwitchRpcTransport {
        switch: switch.clone(),
        neighbor: neighbor_fp,
    });

    // if we are a relay, do the whole adjacency signing thing
    if let Some(my_identity) = my_identity {
        let my_fp = my_identity.public().fingerprint();
        if my_fp < neighbor_fp {
            let mut left_incomplete = AdjacencyDescriptor {
                left: my_fp,
                right: neighbor_fp,
                left_sig: Bytes::new(),
                right_sig: Bytes::new(),
                unix_timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            };
            left_incomplete.left_sig = my_identity.sign(left_incomplete.to_sign().as_bytes());
            let complete = rpc
                .sign_adjacency(left_incomplete)
                .await?
                .context("remote refused to sign off")?;
            graph.modify_graph(|g| g.insert_adjacency(complete.clone()))?;
        }
    }

    // then sync up the *entire* graph they have
    for identity in rpc.all_identities().await? {
        graph.modify_graph(|g| g.insert_identity(identity))?;
    }
    for adjacency in rpc.all_adjacencies().await? {
        graph.modify_graph(|g| g.insert_adjacency(adjacency))?;
    }

    Ok(())
}

struct SwitchRpcTransport {
    switch: WeakHandle<SwitchProcess>,
    neighbor: RelayFingerprint,
}

#[async_trait]
impl RpcTransport for SwitchRpcTransport {
    type Error = anyhow::Error;

    async fn call_raw(&self, req: JrpcRequest) -> Result<JrpcResponse, Self::Error> {
        let (send, recv) = oneshot::channel();
        self.switch
            .send(SwitchMessage::CallLinkRpc(self.neighbor, req, send))
            .await?;
        Ok(recv.await?)
    }
}
