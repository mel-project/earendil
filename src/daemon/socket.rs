use crate::{control_protocol::SendMessageArgs, daemon::DaemonContext};
use bytes::Bytes;
use earendil_crypt::Fingerprint;
use earendil_packet::{Dock, Message};
use smol::channel::Receiver;

pub struct Socket {
    ctx: DaemonContext,
    id: Option<String>,
    dock: Dock,
    recv_incoming: Receiver<(Message, Fingerprint)>,
}

pub struct Endpoint {
    fingerprint: Fingerprint,
    dock: Dock,
}

impl Socket {
    fn bind(ctx: DaemonContext, id: Option<String>, dock: Dock) -> Socket {
        let (send_outgoing, recv_incoming) = smol::channel::bounded(1000);
        ctx.socket_recv_queues.insert(dock, send_outgoing);

        Socket {
            ctx,
            id,
            dock,
            recv_incoming,
        }
    }

    async fn send_to(&self, body: Bytes, endpoint: Endpoint) -> anyhow::Result<()> {
        self.ctx
            .send_message(SendMessageArgs {
                id: self.id.clone(),
                source_dock: self.dock,
                dest_dock: endpoint.dock,
                destination: endpoint.fingerprint,
                content: body,
            })
            .await?;

        Ok(())
    }

    async fn recv_from(&self) -> anyhow::Result<(Bytes, Endpoint)> {
        let (message, fingerprint) = self.recv_incoming.recv().await?;
        let endpoint = Endpoint {
            fingerprint,
            dock: *message.get_source_dock(),
        };

        Ok((message.get_body().clone(), endpoint))
    }
}
