mod surb_store;

use std::{sync::Arc, time::Duration};

use anyhow::Context;
use bytes::Bytes;
use clone_macro::clone;
use dashmap::DashMap;
use earendil_crypt::{AnonEndpoint, RelayEndpoint, RelayFingerprint};
use earendil_packet::{Dock, InnerPacket, Message, RawBody, ReplyDegarbler};
use itertools::Itertools;
use moka::sync::Cache;
use parking_lot::Mutex;
use smol::channel::{Receiver, Sender};
use smolscale::immortal::{Immortal, RespawnStrategy};

use crate::transport_layer::{IncomingMsg, TransportLayer};

use self::surb_store::SurbStore;

/// An implementation of the anonymity layer.
pub struct AnonLayer {
    ctx: AnonLayerCtx,
    _task: Immortal,
}

impl AnonLayer {
    pub fn new(transport: TransportLayer) -> Self {
        let ctx = AnonLayerCtx {
            transport_layer: Arc::new(transport),
            anon_queues: Arc::new(DashMap::new()),
            relay_queues: Arc::new(DashMap::new()),
            rb_store: Arc::new(Mutex::new(SurbStore::new())),
            degarblers: Cache::builder()
                .time_to_live(Duration::from_secs(3600))
                .build(),
        };
        let task = Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([ctx], move || anon_incoming_loop(ctx.clone())),
        );
        Self {
            ctx: ctx.clone(),
            _task: task,
        }
    }

    /// Binds a relay endpoint to the node, creating a new `RelaySocket` for communication.
    pub fn bind_relay(&self, dock: Dock) -> RelaySocket {
        let (sender, receiver) = smol::channel::bounded(1000);
        self.ctx.relay_queues.insert(dock, sender);

        RelaySocket {
            ctx: self.ctx.clone(),
            dock,
            queue: receiver,
        }
    }

    /// Binds an anonymous endpoint to the node, creating a new `AnonSocket` for communication.
    pub fn bind_anon(&self) -> AnonSocket {
        let my_endpoint = AnonEndpoint::random();
        let (sender, receiver) = smol::channel::bounded(1000);
        self.ctx.anon_queues.insert(my_endpoint, sender);

        AnonSocket {
            ctx: self.ctx.clone(),
            my_endpoint,
            queue: receiver,

            remote_surb_counts: DashMap::new(),
        }
    }

    /// Gets the link layer.
    pub fn transport_layer(&self) -> &TransportLayer {
        &self.ctx.transport_layer
    }
}

pub struct AnonSocket {
    ctx: AnonLayerCtx,
    my_endpoint: AnonEndpoint,
    queue: Receiver<(Bytes, RelayEndpoint, usize)>,

    remote_surb_counts: DashMap<RelayFingerprint, usize>,
}

impl Drop for AnonSocket {
    fn drop(&mut self) {
        self.ctx.anon_queues.remove(&self.my_endpoint);
    }
}

impl AnonSocket {
    /// Sends a packet to a particular relay endpoint.
    pub async fn send_to(&self, body: Bytes, dest: RelayEndpoint) -> anyhow::Result<()> {
        self.auto_replenish_surbs(dest.fingerprint).await?;

        self.ctx
            .transport_layer
            .send_forward(
                InnerPacket::Message(Message::new(dest.dock, body, 0)),
                self.my_endpoint,
                dest.fingerprint,
            )
            .await?;
        Ok(())
    }

    /// Receives an incoming packet.
    pub async fn recv_from(&self) -> anyhow::Result<(Bytes, RelayEndpoint)> {
        let (message, source, surb_count) = self.queue.recv().await?;
        tracing::trace!(surb_count, source = debug(source), "surb count gotten");
        self.remote_surb_counts
            .insert(source.fingerprint, surb_count);
        self.auto_replenish_surbs(source.fingerprint).await?;
        Ok((message, source))
    }

    /// Replenishes missing SURBs for the given destination.
    async fn auto_replenish_surbs(&self, fingerprint: RelayFingerprint) -> anyhow::Result<()> {
        if (rand::random::<f64>() < 0.1
            || *self.remote_surb_counts.entry(fingerprint).or_insert(0) < 50)
            && *self.remote_surb_counts.entry(fingerprint).or_insert(0) < 500
        {
            self.replenish_surbs(fingerprint).await?;
        }
        Ok(())
    }

    pub async fn replenish_surbs(&self, fingerprint: RelayFingerprint) -> anyhow::Result<()> {
        // send a batch of 10 surbs
        let surbs = (0..10)
            .map(|_| {
                let (rb, id, degarble) = self.ctx.transport_layer.new_surb(self.my_endpoint)?;
                self.ctx.degarblers.insert(id, degarble);
                anyhow::Ok(rb)
            })
            .try_collect()?;
        self.ctx
            .transport_layer
            .send_forward(InnerPacket::Surbs(surbs), self.my_endpoint, fingerprint)
            .await?;
        Ok(())
    }

    pub fn local_endpoint(&self) -> AnonEndpoint {
        self.my_endpoint
    }
}

#[derive(Clone)]
struct AnonLayerCtx {
    transport_layer: Arc<TransportLayer>,
    anon_queues: Arc<DashMap<AnonEndpoint, Sender<(Bytes, RelayEndpoint, usize)>>>,
    relay_queues: Arc<DashMap<Dock, Sender<(Bytes, AnonEndpoint)>>>,
    rb_store: Arc<Mutex<SurbStore>>,
    degarblers: Cache<u64, ReplyDegarbler>,
}

async fn anon_incoming_loop(ctx: AnonLayerCtx) -> anyhow::Result<()> {
    loop {
        let incoming = ctx.transport_layer.recv().await;
        let fallible = async {
            match incoming {
                IncomingMsg::Forward {
                    from,
                    body: InnerPacket::Message(message),
                } => {
                    tracing::trace!("incoming anon: IncomingMsg::Forward from {from}");
                    let queue = ctx
                        .relay_queues
                        .get(&message.relay_dock)
                        .context("no queue for dock")?;
                    queue.try_send((message.body, from))?;
                }
                IncomingMsg::Forward {
                    from,
                    body: InnerPacket::Surbs(surbs),
                } => {
                    tracing::trace!("incoming anon: IncomingMsg::Forward of Surbs from {from}");
                    for rb in surbs {
                        ctx.rb_store.lock().insert(from, rb);
                    }
                }
                IncomingMsg::Backward { rb_id, body } => {
                    let degarbler = ctx
                        .degarblers
                        .remove(&rb_id)
                        .context(format!("no degarbler for rb_id = {rb_id}"))?;
                    tracing::trace!(
                        "incoming anon: IncomingMsg::Backward with rb_id = {rb_id} for {}",
                        degarbler.my_anon_id()
                    );
                    let mut body: RawBody = *bytemuck::try_from_bytes(&body)
                        .ok()
                        .context("failed to deserialize incoming RawBody")?;
                    let (degarbled, source) = degarbler.degarble(&mut body)?;
                    if let InnerPacket::Message(msg) = degarbled {
                        ctx.anon_queues
                            .get(&degarbler.my_anon_id())
                            .context(format!("no queue for anon id {}", degarbler.my_anon_id()))?
                            .try_send((
                                msg.body,
                                RelayEndpoint::new(source, msg.relay_dock),
                                msg.remaining_surbs,
                            ))?;
                    }
                }
            }
            anyhow::Ok(())
        };
        if let Err(err) = fallible.await {
            tracing::warn!(err = debug(err), "dropping an incoming");
        }
    }
}

pub struct RelaySocket {
    ctx: AnonLayerCtx,
    dock: Dock,
    queue: Receiver<(Bytes, AnonEndpoint)>,
}

impl Drop for RelaySocket {
    fn drop(&mut self) {
        self.ctx.relay_queues.remove(&self.dock);
    }
}

impl RelaySocket {
    /// Sends a packet to a particular anonymous endpoint.
    pub async fn send_to(&self, body: Bytes, anon_endpoint: AnonEndpoint) -> anyhow::Result<()> {
        let (rb, remaining) = self
            .ctx
            .rb_store
            .lock()
            .pop_and_count(anon_endpoint)
            .context(format!("no surb for anon endpoint: {anon_endpoint:?}"))?;
        self.ctx
            .transport_layer
            .send_backwards(rb, Message::new(self.dock, body, remaining))
            .await?;
        Ok(())
    }

    /// Receives an incoming packet.
    pub async fn recv_from(&self) -> anyhow::Result<(Bytes, AnonEndpoint)> {
        let (message, source) = self.queue.recv().await?;
        Ok((message, source))
    }
}
