use std::{sync::Arc, time::Duration};

use anyhow::Context;
use async_trait::async_trait;
use earendil_crypt::RelayFingerprint;
use earendil_topology::RelayGraph;
use haiyuu::{Handle, WeakHandle};
use nanorpc::{JrpcRequest, JrpcResponse, RpcTransport};
use parking_lot::RwLock;
use rand::seq::SliceRandom;

use crate::link_node::{link_protocol::LinkClient, switch_proc::SwitchMessage};

use super::switch_proc::SwitchProcess;

/// A loop to go around the graph and pull relay graph data from our relay neighbors.
pub async fn gossip_pull_graph(graph: Arc<RwLock<RelayGraph>>, switch: Handle<SwitchProcess>) {
    loop {
        if let Err(err) = gossip_pull_once(graph.clone(), switch.clone()).await {
            tracing::warn!(err = debug(err), "failed to gossip once");
        }
        smol::Timer::after(Duration::from_secs(1)).await;
    }
}

async fn gossip_pull_once(
    graph: Arc<RwLock<RelayGraph>>,
    switch: Handle<SwitchProcess>,
) -> anyhow::Result<()> {
    let (send, recv) = oneshot::channel();
    switch.send(SwitchMessage::DumpRelays(send)).await?;
    let relays = recv.await?;
    let chosen_neighbor = relays
        .choose(&mut rand::thread_rng())
        .cloned()
        .context("no relay neighbors connected to the switch")?;
    let rpc = LinkClient(SwitchRpcTransport {
        switch: switch.downgrade(),
        neighbor: chosen_neighbor,
    });

    todo!()
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
