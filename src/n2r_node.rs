mod reply_block_store;

use std::{sync::Arc, time::Duration};

use anyhow::Context;
use bytes::Bytes;
use dashmap::DashMap;
use earendil_crypt::AnonEndpoint;
use earendil_packet::{Dock, InnerPacket, RawBody, ReplyDegarbler};
use moka::sync::Cache;
use parking_lot::Mutex;
use smol::channel::{Receiver, Sender};

use crate::{
    link_node::{IncomingMsg, LinkNode},
    RelayEndpoint,
};

use self::reply_block_store::ReplyBlockStore;

pub struct N2rNode {
    ctx: N2rNodeCtx,
}

impl N2rNode {
    pub fn new(link_node: LinkNode, cfg: N2rConfig) -> Self {
        Self {
            ctx: N2rNodeCtx {
                cfg,
                link_node: Arc::new(link_node),
                anon_queues: Arc::new(DashMap::new()),
                relay_queues: Arc::new(DashMap::new()),
                rb_store: Arc::new(Mutex::new(ReplyBlockStore::new())),
                degarblers: Cache::builder()
                    .time_to_live(Duration::from_secs(60))
                    .build(),
            },
        }
    }
}

#[derive(Clone)]
struct N2rNodeCtx {
    cfg: N2rConfig,
    link_node: Arc<LinkNode>,
    anon_queues: Arc<DashMap<AnonEndpoint, Sender<(Bytes, RelayEndpoint)>>>,
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
                    let queue = ctx
                        .relay_queues
                        .get(&message.relay_dock)
                        .context("no queue for dock")?;
                    queue.try_send((message.body, from))?;
                }
                IncomingMsg::Forward {
                    from,
                    body: InnerPacket::ReplyBlocks(reply_blocks),
                } => {
                    for rb in reply_blocks {
                        ctx.rb_store.lock().insert(from, rb);
                    }
                }
                IncomingMsg::Backward { rb_id, body } => {
                    let degarbler = ctx.degarblers.remove(&rb_id).context("no such degarbler")?;
                    let mut body: RawBody = *bytemuck::try_from_bytes(&body)
                        .ok()
                        .context("failed to deserialize incoming RawBody")?;
                    let (degarbled, source) = degarbler.degarble(&mut body)?;
                    if let InnerPacket::Message(msg) = degarbled {
                        ctx.anon_queues
                            .get(&degarbler.my_anon_id())
                            .context("no queue for this anon id")?
                            .try_send((msg.body, RelayEndpoint::new(source, msg.relay_dock)))?;
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

#[derive(Clone)]
pub struct N2rConfig {}
