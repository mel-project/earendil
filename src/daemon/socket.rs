use crate::{control_protocol::SendMessageArgs, daemon::DaemonContext};
use bytes::{Bytes, BytesMut};
use earendil_crypt::Fingerprint;
use earendil_packet::{Dock, Message};
use smol::channel::Receiver;

pub struct Socket {
    id: Option<String>,
    dock: Dock,
    recv_incoming: Receiver<Message>,
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
            id,
            dock,
            recv_incoming,
        }
    }

    async fn send_to(
        &self,
        ctx: DaemonContext,
        buf: Bytes,
        endpoint: Endpoint,
    ) -> anyhow::Result<()> {
        ctx.send_message(SendMessageArgs {
            id: self.id.clone(),
            source_dock: self.dock,
            dest_dock: endpoint.dock,
            destination: endpoint.fingerprint,
            content: buf,
        })
        .await?;

        Ok(())
    }

    async fn recv_from(
        &self,
        ctx: DaemonContext,
        buf: &mut BytesMut,
    ) -> anyhow::Result<(usize, Endpoint)> {
        if let Some(sender) = ctx.socket_recv_queues.get(&self.dock) {
            match ctx.recv_message().await {
                Some((msg, fingerprint)) => {
                    let _ = sender.send(msg.clone()).await;
                    let endpoint = Endpoint {
                        fingerprint,
                        dock: msg.clone().get_source_dock().clone(),
                    };
                    buf.copy_from_slice(msg.get_body().as_ref());

                    Ok((msg.get_body().len(), endpoint))
                }
                None => anyhow::bail!("no messages"),
            }
        } else {
            anyhow::bail!("no receiver for socket")
        }
    }
}
