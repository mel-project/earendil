use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use bytes::Bytes;
use clone_macro::clone;
use concurrent_queue::ConcurrentQueue;
use earendil_crypt::{AnonDest, RelayFingerprint, SourceId};
use earendil_packet::{Dock, Message};
use futures_util::TryFutureExt;
use rand::Rng;

use smol::channel::{Receiver, Sender};
use smolscale::immortal::{Immortal, RespawnStrategy};

use crate::{
    daemon::context::{
        send_n2r, send_reply, DaemonContext, ANON_IDENTITIES, CLIENT_SOCKET_RECV_QUEUES,
        GLOBAL_IDENTITY, RELAY_SOCKET_RECV_QUEUES,
    },
    socket::SocketRecvError,
};

use super::{AnonEndpoint, RelayEndpoint, SocketSendError};

struct RelayBoundDock {
    fp: RelayFingerprint,
    dock: Dock,
    ctx: DaemonContext,
}

impl Drop for RelayBoundDock {
    fn drop(&mut self) {
        self.ctx
            .get(RELAY_SOCKET_RECV_QUEUES)
            .remove(&RelayEndpoint::new(self.fp, self.dock));
    }
}

#[derive(Clone)]
pub struct N2rRelaySocket {
    bound_dock: Arc<RelayBoundDock>,
    recv_incoming: Receiver<(Message, SourceId)>, // relays can only ever receive communication from clients
    incoming_queue: Arc<ConcurrentQueue<(Bytes, AnonEndpoint)>>,

    send_outgoing: Sender<(Bytes, AnonEndpoint)>,
    _send_batcher: Arc<Immortal>,
}

impl N2rRelaySocket {
    pub fn bind(ctx: DaemonContext, dock: Option<Dock>) -> Self {
        let my_pk = ctx.get(GLOBAL_IDENTITY).public();
        let my_fp = my_pk.fingerprint();
        let dock = if let Some(dock) = dock {
            dock
        } else {
            let mut rand_dock: Dock;
            loop {
                rand_dock = rand::thread_rng().gen();
                if !ctx
                    .get(RELAY_SOCKET_RECV_QUEUES)
                    .contains_key(&RelayEndpoint {
                        fingerprint: my_fp,
                        dock: rand_dock,
                    })
                {
                    break;
                }
            }
            rand_dock
        };
        let bound_dock = Arc::new(RelayBoundDock {
            fp: my_fp,
            dock,
            ctx: ctx.clone(),
        });
        let (send_incoming, recv_incoming) = smol::channel::bounded(1000);
        ctx.get(RELAY_SOCKET_RECV_QUEUES).insert(
            RelayEndpoint {
                fingerprint: my_fp,
                dock,
            },
            send_incoming,
        );

        let (send_outgoing, recv_outgoing) = smol::channel::bounded(10000);
        N2rRelaySocket {
            bound_dock,
            recv_incoming,

            send_outgoing,
            incoming_queue: Arc::new(ConcurrentQueue::unbounded()),

            _send_batcher: Immortal::respawn(
                RespawnStrategy::Immediate,
                clone!([ctx, recv_outgoing], move || relay_send_batcher_loop(
                    ctx.clone(),
                    dock,
                    recv_outgoing.clone()
                )
                .map_err(move |e| tracing::warn!(
                    "send_batcher from global ID {} restarting: {:?}",
                    my_fp,
                    e
                ))),
            )
            .into(),
        }
    }

    pub fn send_to(&self, body: Bytes, endpoint: AnonEndpoint) -> Result<(), SocketSendError> {
        let _ = self.send_outgoing.try_send((body, endpoint));
        Ok(())
    }

    pub async fn recv_from(&self) -> Result<(Bytes, AnonEndpoint), SocketRecvError> {
        loop {
            if let Ok(retval) = self.incoming_queue.pop() {
                return Ok(retval);
            }

            let (message, source) = self.recv_incoming.recv().await.map_err(|e| {
                tracing::debug!("N2rSocket RecvError: {e}");
                SocketRecvError::N2rRecvError
            })?;

            match source {
                SourceId::Anon(anon_dest) => {
                    let endpoint = AnonEndpoint::new(anon_dest, message.source_dock);
                    for batch_member in message.body {
                        self.incoming_queue.push((batch_member, endpoint)).unwrap();
                    }
                }
                _ => return Err(SocketRecvError::N2rRecvError),
            };
        }
    }

    pub fn local_endpoint(&self) -> RelayEndpoint {
        RelayEndpoint::new(self.bound_dock.fp, self.bound_dock.dock)
    }
}

struct ClientBoundDock {
    anon_id: AnonDest,
    dock: Dock,
    ctx: DaemonContext,
}

impl Drop for ClientBoundDock {
    fn drop(&mut self) {
        self.ctx
            .get(CLIENT_SOCKET_RECV_QUEUES)
            .remove(&AnonEndpoint::new(self.anon_id, self.dock));
    }
}

#[derive(Clone)]
pub struct N2rClientSocket {
    bound_dock: Arc<ClientBoundDock>,
    recv_incoming: Receiver<(Message, SourceId)>, // relays can only ever receive communication from clients
    incoming_queue: Arc<ConcurrentQueue<(Bytes, RelayEndpoint)>>,

    send_outgoing: Sender<(Bytes, RelayEndpoint)>,
    _send_batcher: Arc<Immortal>,
}

impl N2rClientSocket {
    pub fn bind(ctx: DaemonContext, dock: Option<Dock>) -> Self {
        let my_anon_id = AnonDest::new();
        let dock = if let Some(dock) = dock {
            dock
        } else {
            let mut rand_dock: Dock;
            loop {
                rand_dock = rand::thread_rng().gen();
                if !ctx
                    .get(CLIENT_SOCKET_RECV_QUEUES)
                    .contains_key(&AnonEndpoint {
                        anon_dest: my_anon_id,
                        dock: rand_dock,
                    })
                {
                    break;
                }
            }
            rand_dock
        };
        let bound_dock = Arc::new(ClientBoundDock {
            anon_id: my_anon_id,
            dock,
            ctx: ctx.clone(),
        });
        let (send_incoming, recv_incoming) = smol::channel::bounded(1000);
        ctx.get(CLIENT_SOCKET_RECV_QUEUES).insert(
            AnonEndpoint {
                anon_dest: my_anon_id,
                dock,
            },
            send_incoming,
        );

        let (send_outgoing, recv_outgoing) = smol::channel::bounded(10000);
        N2rClientSocket {
            bound_dock,
            recv_incoming,

            send_outgoing,
            incoming_queue: Arc::new(ConcurrentQueue::unbounded()),

            _send_batcher: Immortal::respawn(
                RespawnStrategy::Immediate,
                clone!([ctx, recv_outgoing], move || client_send_batcher_loop(
                    ctx.clone(),
                    dock,
                    recv_outgoing.clone()
                )
                .map_err(move |e| tracing::warn!(
                    "send_batcher from anon id {my_anon_id} restarting: {:?}",
                    e
                ))),
            )
            .into(),
        }
    }

    pub fn send_to(&self, body: Bytes, endpoint: RelayEndpoint) -> Result<(), SocketSendError> {
        let _ = self.send_outgoing.try_send((body, endpoint));
        Ok(())
    }

    pub async fn recv_from(&self) -> Result<(Bytes, RelayEndpoint), SocketRecvError> {
        loop {
            if let Ok(retval) = self.incoming_queue.pop() {
                return Ok(retval);
            }

            let (message, source) = self.recv_incoming.recv().await.map_err(|e| {
                tracing::debug!("N2rSocket RecvError: {e}");
                SocketRecvError::N2rRecvError
            })?;

            match source {
                SourceId::Relay(fp) => {
                    let endpoint = RelayEndpoint::new(fp, message.source_dock);
                    for batch_member in message.body {
                        self.incoming_queue.push((batch_member, endpoint)).unwrap();
                    }
                }
                _ => return Err(SocketRecvError::N2rRecvError),
            };
        }
    }

    pub fn local_endpoint(&self) -> AnonEndpoint {
        AnonEndpoint::new(self.bound_dock.anon_id, self.bound_dock.dock)
    }
}

#[tracing::instrument(skip(ctx, recv_outgoing))]
async fn relay_send_batcher_loop(
    ctx: DaemonContext,
    dock: Dock,
    recv_outgoing: Receiver<(Bytes, AnonEndpoint)>,
) -> anyhow::Result<()> {
    let mut batches: HashMap<AnonEndpoint, VecDeque<Bytes>> = HashMap::new();
    loop {
        batches.clear();
        // sleep a little while so that stuff accumulates
        smol::Timer::after(Duration::from_millis(5)).await;
        tracing::trace!("{} packets queued up", recv_outgoing.len());
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
                tracing::trace!("subbatch of size {}", subbatch.len());
                // send the message
                send_reply(
                    &ctx,
                    dock,
                    endpoint.anon_dest,
                    endpoint.dock,
                    subbatch.clone(),
                )
                .await
                .context("send_reply failed")?;
            }
        }
    }
}

#[tracing::instrument(skip(ctx, recv_outgoing))]
async fn client_send_batcher_loop(
    ctx: DaemonContext,
    dock: Dock,
    recv_outgoing: Receiver<(Bytes, RelayEndpoint)>,
) -> anyhow::Result<()> {
    let mut batches: HashMap<RelayEndpoint, VecDeque<Bytes>> = HashMap::new();
    loop {
        batches.clear();
        // sleep a little while so that stuff accumulates
        smol::Timer::after(Duration::from_millis(5)).await;
        tracing::trace!("{} packets queued up", recv_outgoing.len());
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

            let my_anon_id =
                if let Some(anon_id) = ctx.get(ANON_IDENTITIES).get(&endpoint.fingerprint) {
                    anon_id
                } else {
                    let new_anon_id = AnonDest::new();
                    ctx.get(ANON_IDENTITIES)
                        .insert(endpoint.fingerprint, new_anon_id);
                    new_anon_id
                };

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
                tracing::trace!("subbatch of size {}", subbatch.len());
                // send the message
                send_n2r(
                    &ctx,
                    my_anon_id,
                    dock,
                    endpoint.fingerprint,
                    endpoint.dock,
                    subbatch.clone(),
                )
                .await
                .context("send_reply failed")?;
            }
        }
    }
}
