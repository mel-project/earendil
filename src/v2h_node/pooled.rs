use std::{sync::Arc, time::Duration};

use anyhow::Context as _;
use earendil_crypt::HavenEndpoint;
use futures::{future::Shared, AsyncReadExt, FutureExt, TryFutureExt};
use nursery_macro::nursery;
use picomux::PicoMux;
use smol::{
    channel::{Receiver, Sender},
    future::FutureExt as _,
    Task,
};

use crate::v2h_node::stream::HeavyStream;
use crate::v2h_node::HavenPacketConn;

use super::{HavenListener, V2hNodeCtx};

/// HavenPacketConn is heavyweight, non-reliable, and does not come with timeout and keepalive functionality.
///
/// The standard solution in Earendil is to use this struct. [PooledVisitor] represents internally contains one or more HavenPacketConns to every haven destination you might want to connect, and multiplexes many streams on top of each.
///
/// **A note on anonymity**: Different picomux streams returned by the same PooledVisitor may be linkable to each other by the haven. Different [PooledVisitor]s, however, are not linkable to each other.
pub struct PooledVisitor {
    ctx: V2hNodeCtx,
    // one mux per endpoint for now
    pool: moka::future::Cache<HavenEndpoint, Arc<PicoMux>>,
}

impl PooledVisitor {
    /// Creates a new visitor pool.
    pub(super) fn new(ctx: V2hNodeCtx) -> Self {
        Self {
            ctx,
            pool: moka::future::Cache::builder()
                .time_to_idle(Duration::from_secs(3600))
                .build(),
        }
    }

    /// Opens a new picomux stream to the given haven endpoint, attaching the given piece of metadata.
    pub async fn connect(
        &self,
        dest: HavenEndpoint,
        metadata: &[u8],
    ) -> anyhow::Result<picomux::Stream> {
        loop {
            let mux = self
                .pool
                .try_get_with(dest, async {
                    tracing::debug!("pool cache MISS destination={}", dest);
                    let pkt_conn = HavenPacketConn::connect(&self.ctx, dest).await?;
                    tracing::warn!("got HavenPacketConn");
                    let stream = HeavyStream::new(pkt_conn);
                    let (read, write) = stream.split();
                    anyhow::Ok(Arc::new(PicoMux::new(read, write)))
                })
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
            if mux.is_alive() {
                return Ok(mux.open(metadata).await?);
            } else {
                tracing::debug!(dest = debug(dest), "pooled mux already dead, so retrying");
                self.pool.remove(&dest).await;
            }
        }
    }
}

/// This is the haven counterpart to PooledVisitor. It gives a convenient way to manage picomux-over-haven with a familiar interface.
pub struct PooledListener {
    recv_incoming: Receiver<picomux::Stream>,
    _task: Shared<Task<Result<(), Arc<anyhow::Error>>>>,
}

impl PooledListener {
    pub fn new(listener: HavenListener) -> Self {
        let (send_incoming, recv_incoming) = smol::channel::bounded(1);
        Self {
            recv_incoming,
            _task: smolscale::spawn(
                pooled_listener_task(listener, send_incoming).map_err(Arc::new),
            )
            .shared(),
        }
    }

    pub async fn accept(&self) -> anyhow::Result<picomux::Stream> {
        async {
            if let Ok(val) = self.recv_incoming.recv().await {
                Ok(val)
            } else {
                smol::future::pending().await
            }
        }
        .or(async {
            let res = self._task.clone().await;
            Err(anyhow::anyhow!(res.unwrap_err()))
        })
        .await
    }
}

async fn pooled_listener_task(
    listener: HavenListener,
    send_incoming: Sender<picomux::Stream>,
) -> anyhow::Result<()> {
    nursery!({
        loop {
            let conn = HeavyStream::new(listener.accept().await.context("inner listener failed")?);
            let (read, write) = conn.split();
            let mux = PicoMux::new(read, write);
            let send_incoming = &send_incoming;
            let t: Task<anyhow::Result<()>> = spawn!(async move {
                loop {
                    let strm = mux.accept().await?;
                    let _ = send_incoming.send(strm).await;
                }
            });
            t.detach();
        }
    })
}
