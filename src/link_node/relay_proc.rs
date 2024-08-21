use std::convert::Infallible;

use earendil_packet::{RawPacket, RawPacketWithNext};
use haiyuu::Handle;

use super::neighbors_proc::{NeighborMessage, NeighborProcess};

pub struct RelayProcess {
    neigh_proc: Handle<NeighborProcess>,
}

impl RelayProcess {
    /// Peel and forward a particular raw packet.
    fn peel_forward(&mut self, packet: RawPacketWithNext) -> anyhow::Result<()> {
        todo!()
    }
}

impl haiyuu::Process for RelayProcess {
    type Message = RelayMessage;
    type Output = Infallible;

    async fn run(&mut self, mailbox: &mut haiyuu::Mailbox<Self>) -> Infallible {
        self.neigh_proc
            .send(NeighborMessage::SubscribeRelay(mailbox.handle()))
            .await
            .expect("failed to register with the neighbor process");
        loop {
            match mailbox.recv().await {
                RelayMessage::PeelForward(packet) => {
                    if let Err(err) = self.peel_forward(packet) {
                        tracing::warn!(err = debug(err), "failed to peel and forward");
                    }
                }
            }
        }
    }
}

pub enum RelayMessage {
    PeelForward(RawPacketWithNext),
}
