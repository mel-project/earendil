use std::{
    collections::{HashMap, VecDeque},
    fmt::Display,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use crate::daemon::{log_error, DaemonContext};
use bytes::Bytes;
use clone_macro::clone;
use concurrent_queue::ConcurrentQueue;
use earendil_crypt::{Fingerprint, IdentitySecret};
use earendil_packet::{Dock, Message};
use futures_util::TryFutureExt;
use rand::Rng;
use serde::{Deserialize, Serialize};
use smol::channel::{Receiver, Sender};
use smolscale::immortal::{Immortal, RespawnStrategy};

use super::socket::{SocketRecvError, SocketSendError};

#[derive(Clone)]
pub struct N2rSocket {
    ctx: DaemonContext,
    anon_id: Option<IdentitySecret>,
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

        let (send_msg, recv_msg) = smol::channel::bounded(1000);
        let _send_batcher = Arc::new(Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([ctx, anon_id, recv_msg], move || send_batcher_loop(
                ctx.clone(),
                anon_id.clone(),
                dock,
                recv_msg.clone()
            )
            .map_err(log_error("send_batcher"))),
        ));
        N2rSocket {
            ctx,
            anon_id,
            bound_dock,
            recv_incoming,
            send_outgoing: send_msg,
            incoming_queue: Arc::new(ConcurrentQueue::unbounded()),
            _send_batcher,
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
    anon_id: Option<IdentitySecret>,
    dock: Dock,
    recv_msg: Receiver<(Bytes, Endpoint)>,
) -> anyhow::Result<()> {
    let mut batches: HashMap<Endpoint, VecDeque<Bytes>> = HashMap::new();
    loop {
        batches.clear();
        // sleep a little while so that stuff accumulates
        smol::Timer::after(Duration::from_millis(10)).await;
        let (msg, dest) = recv_msg.recv().await?;
        batches.entry(dest).or_default().push_back(msg);
        // try to receive more, as long as they're immediately available
        while let Ok((msg, dest)) = recv_msg.try_recv() {
            batches.entry(dest).or_default().push_back(msg);
        }
        // go through all the batches
        let mut subbatch = vec![];
        for (endpoint, batch) in batches.iter_mut() {
            // take things out until a limit is hit
            const LIMIT: usize = 8192;
            const OVERHEAD: usize = 10; // conservative
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
            // send the message
            ctx.send_message(
                anon_id.clone(),
                dock,
                endpoint.fingerprint,
                endpoint.dock,
                subbatch.clone(),
            )
            .await?;
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

#[derive(Copy, Clone, Deserialize, Serialize, Hash, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub struct Endpoint {
    pub fingerprint: Fingerprint,
    pub dock: Dock,
}

impl Endpoint {
    pub fn new(fingerprint: Fingerprint, dock: Dock) -> Endpoint {
        Endpoint { fingerprint, dock }
    }
}

impl Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:{}", self.fingerprint, self.dock)
    }
}

impl FromStr for Endpoint {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let elems: Vec<&str> = s.split(':').collect();
        if elems.len() != 2 {
            return Err(anyhow::anyhow!(
                "Wrong endpoint format! Endpoint format should be fingerprint:dock"
            ));
        }
        let fp = Fingerprint::from_str(elems[0])?;
        let dock = u32::from_str(elems[1])?;
        Ok(Endpoint::new(fp, dock))
    }
}
