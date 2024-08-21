mod link_proc;

use std::convert::Infallible;

use bytes::Bytes;
use earendil_crypt::{ClientId, RelayFingerprint};
use earendil_packet::{Message, RawPacketWithNext};
use haiyuu::WeakHandle;

use super::relay_proc::RelayProcess;

pub struct NeighborProcess {
    relay: Option<WeakHandle<RelayProcess>>,
}

impl NeighborProcess {
    pub fn new() -> Self {
        todo!()
    }
}

impl haiyuu::Process for NeighborProcess {
    type Message = NeighborMessage;

    type Output = Infallible;

    async fn run(&mut self, mailbox: &mut haiyuu::Mailbox<Self>) -> Infallible {
        loop {
            let fallible = async {
                match mailbox.recv().await {
                    NeighborMessage::ToRelay(_, _) => todo!(),
                    NeighborMessage::ToClient(_, _) => todo!(),
                    NeighborMessage::SubscribeRelay(handle) => self.relay = Some(handle),
                    NeighborMessage::FromClient(_, _) => todo!(),
                    NeighborMessage::FromRelay(_, _) => todo!(),
                }
                anyhow::Ok(())
            };
            if let Err(err) = fallible.await {
                tracing::warn!(err = debug(err), "failed to handle")
            }
        }
    }
}

pub enum NeighborMessage {
    ToRelay(Bytes, RelayFingerprint),
    ToClient(Bytes, ClientId),
    SubscribeRelay(WeakHandle<RelayProcess>),

    FromClient(Bytes, ClientId),
    FromRelay(Bytes, RelayFingerprint),
}
