use std::{collections::BTreeMap, convert::Infallible};

use bytes::Bytes;
use earendil_packet::RawPacketWithNext;

use haiyuu::Process;

use smol::channel::Sender;

use crate::config::OutRouteConfig;

use super::{
    gossip::graph_gossip_loop,
    netgraph::NetGraph,
    switch_proc::{SwitchMessage, SwitchProcess},
    IncomingMsg,
};

pub struct ClientProcess {
    identity: u64,
    out_routes: BTreeMap<String, OutRouteConfig>,
    relay_graph: NetGraph,
    send_incoming: Sender<IncomingMsg>,
}

impl ClientProcess {
    pub fn new(
        identity: u64,
        out_routes: BTreeMap<String, OutRouteConfig>,
        relay_graph: NetGraph,
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
        let switch = SwitchProcess::new_client(
            self.identity,
            mailbox.handle(),
            self.relay_graph.clone(),
            self.out_routes.clone(),
        )
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
                    let relay = self.relay_graph.closest_neigh_to(raw.next_peeler);
                    if let Some(relay) = relay {
                        let _ = switch.send_or_drop(SwitchMessage::ToRelay(
                            bytemuck::bytes_of(&*raw).to_vec().into(),
                            relay,
                        ));
                    } else {
                        tracing::warn!(next = debug(raw.next_peeler), "unable to route to next")
                    }
                }
                ClientMsg::Backward(rb_id, body) => {
                    let _ = self
                        .send_incoming
                        .try_send(IncomingMsg::Backward { rb_id, body });
                }
            }
        }
    }
}

pub enum ClientMsg {
    Forward(Box<RawPacketWithNext>),
    Backward(u64, Bytes),
}
