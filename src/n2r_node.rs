mod reply_block_store;

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

use crate::link_node::{IncomingMsg, LinkNode};

use self::reply_block_store::ReplyBlockStore;

/// An implementation of the N2R layer.
pub struct N2rNode {
    ctx: N2rNodeCtx,
    _task: Immortal,
}

impl N2rNode {
    pub fn new(link_node: LinkNode, cfg: N2rConfig) -> Self {
        let ctx = N2rNodeCtx {
            cfg,
            link_node: Arc::new(link_node),
            anon_queues: Arc::new(DashMap::new()),
            relay_queues: Arc::new(DashMap::new()),
            rb_store: Arc::new(Mutex::new(ReplyBlockStore::new())),
            degarblers: Cache::builder()
                .time_to_live(Duration::from_secs(3600))
                .build(),
        };
        let task = Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([ctx], move || n2r_incoming_loop(ctx.clone())),
        );
        Self {
            ctx: ctx.clone(),
            _task: task,
        }
    }

    /// Binds a relay endpoint to the node, creating a new `N2rRelaySocket` for communication.
    pub fn bind_relay(&self, dock: Dock) -> N2rRelaySocket {
        let (sender, receiver) = smol::channel::bounded(100);
        self.ctx.relay_queues.insert(dock, sender);

        N2rRelaySocket {
            ctx: self.ctx.clone(),
            dock,
            queue: receiver,
        }
    }

    /// Binds an anonymous endpoint to the node, creating a new `N2rAnonSocket` for communication.
    pub fn bind_anon(&self) -> N2rAnonSocket {
        let my_endpoint = AnonEndpoint::random();
        let (sender, receiver) = smol::channel::bounded(100);
        self.ctx.anon_queues.insert(my_endpoint, sender);

        N2rAnonSocket {
            ctx: self.ctx.clone(),
            my_endpoint,
            queue: receiver,

            remote_surb_counts: DashMap::new(),
        }
    }

    /// Gets the link layer.
    pub fn link_node(&self) -> &LinkNode {
        &self.ctx.link_node
    }
}

pub struct N2rAnonSocket {
    ctx: N2rNodeCtx,
    my_endpoint: AnonEndpoint,
    queue: Receiver<(Bytes, RelayEndpoint, usize)>,

    remote_surb_counts: DashMap<RelayFingerprint, usize>,
}

impl Drop for N2rAnonSocket {
    fn drop(&mut self) {
        self.ctx.anon_queues.remove(&self.my_endpoint);
    }
}

impl N2rAnonSocket {
    /// Sends a packet to a particular relay endpoint.
    pub async fn send_to(&self, body: Bytes, dest: RelayEndpoint) -> anyhow::Result<()> {
        self.replenish_surb(dest.fingerprint).await?;

        self.ctx
            .link_node
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
        tracing::debug!(surb_count, source = debug(source), "surb count gotten");
        self.remote_surb_counts
            .insert(source.fingerprint, surb_count);
        self.replenish_surb(source.fingerprint).await?;
        Ok((message, source))
    }

    /// Replenishes missing SURBs for the given destination.
    pub async fn replenish_surb(&self, fingerprint: RelayFingerprint) -> anyhow::Result<()> {
        // send a batch of 10 surbs
        if (rand::random::<f64>() < 0.1
            || *self.remote_surb_counts.entry(fingerprint).or_insert(0) < 50)
            && *self.remote_surb_counts.entry(fingerprint).or_insert(0) < 500
        {
            let surbs = (0..10)
                .map(|_| {
                    let (rb, id, degarble) = self
                        .ctx
                        .link_node
                        .surb_from(self.my_endpoint, fingerprint)?;
                    self.ctx.degarblers.insert(id, degarble);
                    anyhow::Ok(rb)
                })
                .try_collect()?;
            self.ctx
                .link_node
                .send_forward(InnerPacket::Surbs(surbs), self.my_endpoint, fingerprint)
                .await?;
        }
        Ok(())
    }

    pub fn local_endpoint(&self) -> AnonEndpoint {
        self.my_endpoint
    }
}

#[derive(Clone)]
struct N2rNodeCtx {
    cfg: N2rConfig,
    link_node: Arc<LinkNode>,
    anon_queues: Arc<DashMap<AnonEndpoint, Sender<(Bytes, RelayEndpoint, usize)>>>,
    relay_queues: Arc<DashMap<Dock, Sender<(Bytes, AnonEndpoint)>>>,
    rb_store: Arc<Mutex<ReplyBlockStore>>,
    degarblers: Cache<u64, ReplyDegarbler>,
}

async fn n2r_incoming_loop(ctx: N2rNodeCtx) -> anyhow::Result<()> {
    loop {
        let incoming = ctx.link_node.recv().await;
        let fallible = async {
            match incoming {
                IncomingMsg::Forward {
                    from,
                    body: InnerPacket::Message(message),
                } => {
                    tracing::trace!("incoming n2r: IncomingMsg::Forward from {from}");
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
                    tracing::trace!("incoming n2r: IncomingMsg::Forward of Surbs from {from}");
                    for rb in surbs {
                        ctx.rb_store.lock().insert(from, rb);
                    }
                }
                IncomingMsg::Backward { rb_id, body } => {
                    let degarbler = ctx
                        .degarblers
                        .remove(&rb_id)
                        .context("no degarbler for rb_id = {rb_id}")?;
                    tracing::trace!(
                        "incoming n2r: IncomingMsg::Backward with rb_id = {rb_id} for {}",
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

pub struct N2rRelaySocket {
    ctx: N2rNodeCtx,
    dock: Dock,
    queue: Receiver<(Bytes, AnonEndpoint)>,
}

impl Drop for N2rRelaySocket {
    fn drop(&mut self) {
        self.ctx.relay_queues.remove(&self.dock);
    }
}

impl N2rRelaySocket {
    /// Sends a packet to a particular anonymous endpoint.
    pub async fn send_to(&self, body: Bytes, anon_endpoint: AnonEndpoint) -> anyhow::Result<()> {
        let (rb, remaining) = self
            .ctx
            .rb_store
            .lock()
            .pop_and_count(anon_endpoint)
            .context(format!("no surb for anon endpoint: {:?}", anon_endpoint))?;
        self.ctx
            .link_node
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

#[derive(Clone)]
pub struct N2rConfig {}
