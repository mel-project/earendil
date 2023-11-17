use std::sync::Arc;

use bytes::Bytes;
use earendil_crypt::{Fingerprint, IdentitySecret};
use earendil_packet::{Dock, Message};
use rand::Rng;
use smol::channel::Receiver;

use crate::daemon::context::DaemonContext;

use super::socket::{Endpoint, SocketRecvError, SocketSendError};

pub struct N2rSocket {
    ctx: DaemonContext,
    anon_id: IdentitySecret,
    bound_dock: Arc<BoundDock>,
    recv_incoming: Receiver<(Message, Fingerprint)>,
}

struct BoundDock {
    fp: Fingerprint,
    dock: Dock,
    ctx: DaemonContext,
}

impl N2rSocket {
    /// Binds an N2R socket. anon_id indicates the anonymous ID to use. If this is not given, then the node's own identity will be used, which will not function properly if this is not running on a relay.
    pub fn bind(ctx: DaemonContext, anon_id: IdentitySecret, dock: Option<Dock>) -> N2rSocket {
        let our_fingerprint = anon_id.public().fingerprint();
        let dock = if let Some(dock) = dock {
            dock
        } else {
            let mut rand_dock: Dock;
            loop {
                rand_dock = rand::thread_rng().gen();
                if !ctx.socket_recv_queues.contains_key(&Endpoint {
                    fingerprint: our_fingerprint,
                    dock: rand_dock,
                }) {
                    break;
                }
            }
            rand_dock
        };
        let bound_dock = Arc::new(BoundDock {
            fp: our_fingerprint,
            dock,
            ctx: ctx.clone(),
        });
        let (send_outgoing, recv_incoming) = smol::channel::bounded(1000);
        ctx.socket_recv_queues.insert(
            Endpoint {
                fingerprint: our_fingerprint,
                dock,
            },
            send_outgoing,
        );

        N2rSocket {
            ctx,
            anon_id,
            bound_dock,
            recv_incoming,
        }
    }

    pub async fn send_to(&self, body: Bytes, endpoint: Endpoint) -> Result<(), SocketSendError> {
        self.ctx
            .send_message(
                self.anon_id.clone(),
                self.bound_dock.dock,
                endpoint.fingerprint,
                endpoint.dock,
                body,
            )
            .await?;
        Ok(())
    }

    pub async fn recv_from(&self) -> Result<(Bytes, Endpoint), SocketRecvError> {
        let (message, fingerprint) = self.recv_incoming.recv().await.map_err(|e| {
            log::debug!("N2rSocket RecvError: {e}");
            SocketRecvError::N2rRecvError
        })?;
        let endpoint = Endpoint::new(fingerprint, message.source_dock);
        Ok((message.body, endpoint))
    }

    pub fn skt_info(&self) -> Endpoint {
        Endpoint::new(self.bound_dock.fp, self.bound_dock.dock)
    }
}

impl Drop for BoundDock {
    fn drop(&mut self) {
        self.ctx
            .socket_recv_queues
            .remove(&Endpoint::new(self.fp, self.dock));
    }
}
