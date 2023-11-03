use std::sync::Arc;

use crate::daemon::DaemonContext;
use bytes::Bytes;
use earendil_crypt::{Fingerprint, IdentitySecret};
use earendil_packet::{Dock, Message};
use rand::Rng;
use serde::{Deserialize, Serialize};
use smol::channel::Receiver;

#[derive(Clone)]
pub struct N2rSocket {
    ctx: DaemonContext,
    anon_id: Option<IdentitySecret>,
    bound_dock: Arc<BoundDock>,
    recv_incoming: Receiver<(Message, Fingerprint)>,
}

struct BoundDock {
    fp: Fingerprint,
    dock: Dock,
    ctx: DaemonContext,
}

#[derive(Copy, Clone, Deserialize, Serialize, Hash, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub struct Endpoint {
    fingerprint: Fingerprint,
    dock: Dock,
}

impl N2rSocket {
    /// Binds an N2R socket. anon_id indicates the anonymous ID to use. If this is not given, then the node's own identity will be used, which will not function properly if this is not running on a relay.
    pub fn bind(
        ctx: DaemonContext,
        anon_id: Option<IdentitySecret>,
        dock: Option<Dock>,
    ) -> N2rSocket {
        let our_fingerprint = anon_id
            .as_ref()
            .map(|anon_id| anon_id.public().fingerprint())
            .unwrap_or_else(|| ctx.identity.public().fingerprint());
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

    pub async fn send_to(&self, body: Bytes, endpoint: Endpoint) -> anyhow::Result<()> {
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

    pub async fn recv_from(&self) -> anyhow::Result<(Bytes, Endpoint)> {
        let (message, fingerprint) = self.recv_incoming.recv().await?;
        let endpoint = Endpoint::new(fingerprint, message.source_dock);

        Ok((message.body, endpoint))
    }
}

impl Drop for BoundDock {
    fn drop(&mut self) {
        self.ctx
            .socket_recv_queues
            .remove(&Endpoint::new(self.fp, self.dock));
    }
}

impl Endpoint {
    pub fn new(fingerprint: Fingerprint, dock: Dock) -> Endpoint {
        Endpoint { fingerprint, dock }
    }
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }
}
