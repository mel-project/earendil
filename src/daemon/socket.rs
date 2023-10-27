use std::sync::Arc;

use crate::{control_protocol::SendMessageArgs, daemon::DaemonContext};
use bytes::Bytes;
use earendil_crypt::Fingerprint;
use earendil_packet::{Dock, Message};
use rand::Rng;
use serde::{Deserialize, Serialize};
use smol::channel::Receiver;

#[derive(Clone)]
pub struct Socket {
    ctx: DaemonContext,
    id: Option<String>,
    bound_dock: Arc<BoundDock>,
    recv_incoming: Receiver<(Message, Fingerprint)>,
}

struct BoundDock {
    dock: Dock,
    ctx: DaemonContext,
}

#[derive(Copy, Clone, Deserialize, Serialize)]
pub struct Endpoint {
    fingerprint: Fingerprint,
    dock: Dock,
}

impl Socket {
    pub fn bind(ctx: DaemonContext, id: Option<String>, dock: Option<Dock>) -> Socket {
        let dock = if let Some(dock) = dock {
            dock
        } else {
            let mut rand_dock: Dock;
            loop {
                rand_dock = rand::thread_rng().gen();
                if !ctx.socket_recv_queues.contains_key(&rand_dock) {
                    break;
                }
            }
            rand_dock
        };
        let bound_dock = Arc::new(BoundDock {
            dock,
            ctx: ctx.clone(),
        });
        let (send_outgoing, recv_incoming) = smol::channel::bounded(1000);
        ctx.socket_recv_queues.insert(dock, send_outgoing);

        Socket {
            ctx,
            id,
            bound_dock,
            recv_incoming,
        }
    }

    pub async fn send_to(&self, body: Bytes, endpoint: Endpoint) -> anyhow::Result<()> {
        self.ctx
            .send_message(SendMessageArgs {
                id: self.id.clone(),
                source_dock: self.bound_dock.dock,
                dest_dock: endpoint.dock,
                destination: endpoint.fingerprint,
                content: body,
            })
            .await?;

        Ok(())
    }

    pub async fn recv_from(&self) -> anyhow::Result<(Bytes, Endpoint)> {
        let (message, fingerprint) = self.recv_incoming.recv().await?;
        let endpoint = Endpoint::new(fingerprint, *message.get_source_dock());

        Ok((message.get_body().clone(), endpoint))
    }
}

impl Drop for BoundDock {
    fn drop(&mut self) {
        self.ctx.socket_recv_queues.remove(&self.dock);
    }
}

impl Endpoint {
    pub fn new(fingerprint: Fingerprint, dock: Dock) -> Endpoint {
        Endpoint { fingerprint, dock }
    }
}
