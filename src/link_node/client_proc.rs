use std::{collections::BTreeMap, convert::Infallible, sync::Arc};

use bytes::Bytes;
use earendil_packet::RawPacketWithNext;
use earendil_topology::RelayGraph;
use haiyuu::Process;
use parking_lot::RwLock;
use smol::channel::Sender;

use crate::config::OutRouteConfig;

use super::{
    gossip::graph_gossip_loop,
    switch_proc::{SwitchMessage, SwitchProcess},
    IncomingMsg,
};

pub struct ClientProcess {
    identity: u64,
    out_routes: BTreeMap<String, OutRouteConfig>,
    relay_graph: Arc<RwLock<RelayGraph>>,
    send_incoming: Sender<IncomingMsg>,
}

impl ClientProcess {
    pub fn new(
        identity: u64,
        out_routes: BTreeMap<String, OutRouteConfig>,
        relay_graph: Arc<RwLock<RelayGraph>>,
        send_incoming: Sender<IncomingMsg>,
    ) -> Self {
        Self {
            identity,
            out_routes,
            send_incoming,
            relay_graph,
        }
    }
}

impl Process for ClientProcess {
    type Message = ClientMsg;

    type Output = Infallible;

    async fn run(&mut self, mailbox: &mut haiyuu::Mailbox<Self>) -> Self::Output {
        let switch =
            SwitchProcess::new_client(self.identity, mailbox.handle(), self.out_routes.clone())
                .spawn_smolscale();
        let _gossip_loop = smolscale::spawn(graph_gossip_loop(
            None,
            self.relay_graph.clone(),
            switch.downgrade(),
        ));
        loop {
            let msg = mailbox.recv().await;
            match msg {
                ClientMsg::Forward(raw) => {
                    let _ = switch
                        .send(SwitchMessage::ToRandomRelay(
                            bytemuck::bytes_of(&raw).to_vec().into(),
                        ))
                        .await;
                }
                ClientMsg::Backward(rb_id, body) => {
                    let _ = self
                        .send_incoming
                        .send(IncomingMsg::Backward { rb_id, body })
                        .await;
                }
            }
        }
    }
}

pub enum ClientMsg {
    Forward(RawPacketWithNext),
    Backward(u64, Bytes),
}
