use std::{collections::BTreeMap, convert::Infallible};

use bytes::Bytes;
use earendil_packet::RawPacketWithNext;
use haiyuu::Process;
use smol::channel::Sender;

use crate::config::OutRouteConfig;

use super::{
    switch_proc::{SwitchMessage, SwitchProcess},
    IncomingMsg,
};

pub struct ClientProcess {
    identity: u64,
    out_routes: BTreeMap<String, OutRouteConfig>,

    send_incoming: Sender<IncomingMsg>,
}

impl Process for ClientProcess {
    type Message = ClientMsg;

    type Output = Infallible;

    async fn run(&mut self, mailbox: &mut haiyuu::Mailbox<Self>) -> Self::Output {
        let switch =
            SwitchProcess::new_client(self.identity, mailbox.handle(), self.out_routes.clone())
                .spawn_smolscale();
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
