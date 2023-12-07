use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use clone_macro::clone;
use concurrent_queue::ConcurrentQueue;
use earendil_crypt::{Fingerprint, IdentitySecret};
use earendil_packet::{Dock, Message};
use futures_util::TryFutureExt;
use rand::Rng;

use smol::channel::{Receiver, Sender};
use smolscale::immortal::{Immortal, RespawnStrategy};

use crate::{daemon::context::DaemonContext, log_error, socket::SocketRecvError};

use super::{Endpoint, SocketSendError};

#[derive(Clone)]
pub struct N2rSocket {
    bound_dock: Arc<BoundDock>,
    recv_incoming: Receiver<(Message, Fingerprint)>,
    incoming_queue: Arc<ConcurrentQueue<(Bytes, Endpoint)>>,

    send_outgoing: Sender<(Bytes, Endpoint)>,
    _send_batcher: Arc<Immortal>,
}

struct BoundDock {
    fp: Fingerprint,
    dock: Dock,
    ctx: DaemonContext,
}

impl N2rSocket {
    /// Binds an N2R socket.
    pub fn bind(ctx: DaemonContext, idsk: IdentitySecret, dock: Option<Dock>) -> N2rSocket {
        let our_fingerprint = idsk.public().fingerprint();
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
        let (send_incoming, recv_incoming) = smol::channel::bounded(1000);
        ctx.socket_recv_queues.insert(
            Endpoint {
                fingerprint: our_fingerprint,
                dock,
            },
            send_incoming,
        );

        let (send_outgoing, recv_outgoing) = smol::channel::bounded(10000);
        N2rSocket {
            bound_dock,
            recv_incoming,

            send_outgoing,
            incoming_queue: Arc::new(ConcurrentQueue::unbounded()),

            _send_batcher: Immortal::respawn(
                RespawnStrategy::Immediate,
                clone!([ctx, recv_outgoing], move || send_batcher_loop(
                    ctx.clone(),
                    idsk,
                    dock,
                    recv_outgoing.clone()
                )
                .map_err(log_error("send_batcher"))),
            )
            .into(),
        }
    }

    pub async fn send_to(&self, body: Bytes, endpoint: Endpoint) -> Result<(), SocketSendError> {
        let _ = self.send_outgoing.send((body, endpoint)).await;
        Ok(())
    }

    pub async fn recv_from(&self) -> Result<(Bytes, Endpoint), SocketRecvError> {
        loop {
            if let Ok(retval) = self.incoming_queue.pop() {
                return Ok(retval);
            }

            let (message, fingerprint) = self.recv_incoming.recv().await.map_err(|e| {
                log::debug!("N2rSocket RecvError: {e}");
                SocketRecvError::N2rRecvError
            })?;
            let endpoint = Endpoint::new(fingerprint, message.source_dock);
            for batch_member in message.body {
                self.incoming_queue.push((batch_member, endpoint)).unwrap();
            }
        }
    }

    pub fn local_endpoint(&self) -> Endpoint {
        Endpoint::new(self.bound_dock.fp, self.bound_dock.dock)
    }
}

async fn send_batcher_loop(
    ctx: DaemonContext,
    isk: IdentitySecret,
    dock: Dock,
    recv_outgoing: Receiver<(Bytes, Endpoint)>,
) -> anyhow::Result<()> {
    let mut batches: HashMap<Endpoint, VecDeque<Bytes>> = HashMap::new();
    loop {
        batches.clear();
        // sleep a little while so that stuff accumulates
        smol::Timer::after(Duration::from_millis(5)).await;
        log::trace!("{} packets queued up", recv_outgoing.len());
        let (msg, dest) = recv_outgoing.recv().await?;
        batches.entry(dest).or_default().push_back(msg);
        // try to receive more, as long as they're immediately available
        while let Ok((msg, dest)) = recv_outgoing.try_recv() {
            batches.entry(dest).or_default().push_back(msg);
        }
        // go through all the batches
        let mut subbatch = vec![];
        for (endpoint, batch) in batches.iter_mut() {
            // take things out until a limit is hit
            const LIMIT: usize = 8192;
            const OVERHEAD: usize = 10; // conservative
            while !batch.is_empty() {
                let mut current_size = 0;
                // we split the batch into subbatches, each of which cannot be too big
                subbatch.clear(); // reuse memory rather than reallocate
                while let Some(first) = batch.pop_front() {
                    let next_size = current_size + first.len() + OVERHEAD;
                    if next_size > LIMIT {
                        batch.push_front(first);
                        break;
                    }
                    subbatch.push(first);
                    current_size = next_size;
                }
                log::trace!("subbatch of size {}", subbatch.len());
                // send the message
                ctx.send_message(
                    isk,
                    dock,
                    endpoint.fingerprint,
                    endpoint.dock,
                    subbatch.clone(),
                )
                .await?;
            }
        }
    }
}

impl Drop for BoundDock {
    fn drop(&mut self) {
        self.ctx
            .socket_recv_queues
            .remove(&Endpoint::new(self.fp, self.dock));
    }
}
