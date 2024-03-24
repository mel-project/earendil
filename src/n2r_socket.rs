use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
    sync::Arc,
};
mod queues;
use anyhow::Context;
use bytes::Bytes;

use earendil_crypt::{AnonEndpoint, RelayFingerprint};
use earendil_packet::Dock;
use serde::{Deserialize, Serialize};
use smol::future::FutureExt as _;

use crate::{
    context::{DaemonContext, MY_RELAY_IDENTITY},
    n2r,
};

use self::queues::{new_client_queue, new_relay_queue, QueueReceiver};

#[derive(Copy, Clone, Deserialize, Serialize, Hash, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub struct RelayEndpoint {
    pub fingerprint: RelayFingerprint,
    pub dock: Dock,
}

impl RelayEndpoint {
    pub fn new(fingerprint: RelayFingerprint, dock: Dock) -> Self {
        Self { fingerprint, dock }
    }
}

impl Display for RelayEndpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.fingerprint, self.dock)
    }
}

impl FromStr for RelayEndpoint {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("invalid relay endpoint format"));
        }
        let fingerprint = RelayFingerprint::from_str(parts[0])?;
        let dock = Dock::from_str(parts[1])?;
        Ok(RelayEndpoint::new(fingerprint, dock))
    }
}

#[derive(Clone)]
pub struct N2rRelaySocket {
    ctx: DaemonContext,
    dock: Dock,
    recv_incoming: Arc<QueueReceiver<(Bytes, AnonEndpoint)>>, // relays can only ever receive communication from clients
}

impl N2rRelaySocket {
    pub fn bind(ctx: DaemonContext, dock: Option<Dock>) -> anyhow::Result<Self> {
        if ctx.init().is_client() {
            anyhow::bail!("cannot bind a relay socket on a client")
        }

        let (dock, recv_incoming) = if let Some(dock) = dock {
            (dock, new_relay_queue(&ctx, dock)?)
        } else {
            loop {
                let dock = rand::random();
                if let Ok(val) = new_relay_queue(&ctx, dock) {
                    break (dock, val);
                }
            }
        };

        Ok(N2rRelaySocket {
            ctx,
            dock,
            recv_incoming: Arc::new(recv_incoming),
        })
    }

    pub async fn send_to(&self, body: Bytes, endpoint: AnonEndpoint) -> anyhow::Result<()> {
        n2r::send_backward(&self.ctx, self.dock, endpoint, body).await?;
        Ok(())
    }

    pub async fn recv_from(&self) -> anyhow::Result<(Bytes, AnonEndpoint)> {
        let (message, source) = self.recv_incoming.recv().await?;

        Ok((message, source))
    }

    pub fn local_endpoint(&self) -> RelayEndpoint {
        RelayEndpoint::new(
            self.ctx
                .get(MY_RELAY_IDENTITY)
                .unwrap()
                .public()
                .fingerprint(),
            self.dock,
        )
    }
}

#[derive(Clone)]
pub struct N2rClientSocket {
    ctx: DaemonContext,
    endpoint: AnonEndpoint,
    recv_incoming: Arc<QueueReceiver<(Bytes, RelayEndpoint)>>, // relays can only ever receive communication from clients
}

impl N2rClientSocket {
    pub fn bind(ctx: DaemonContext, my_anon_id: AnonEndpoint) -> anyhow::Result<Self> {
        let recv_incoming = new_client_queue(&ctx, my_anon_id)?;

        Ok(N2rClientSocket {
            ctx,
            endpoint: my_anon_id,
            recv_incoming: Arc::new(recv_incoming),
        })
    }

    pub async fn send_to(&self, body: Bytes, endpoint: RelayEndpoint) -> anyhow::Result<()> {
        n2r::send_forward(
            &self.ctx,
            self.endpoint,
            endpoint.fingerprint,
            endpoint.dock,
            body,
        )
        .await
        .context("n2r send_forward failed")?;
        Ok(())
    }

    pub async fn supply_reply_blocks(&self, fingerprint: RelayFingerprint) -> anyhow::Result<()> {
        n2r::replenish_remote_rb(&self.ctx, self.endpoint, fingerprint).await?;
        Ok(())
    }

    pub async fn recv_from(&self) -> anyhow::Result<(Bytes, RelayEndpoint)> {
        let (message, source) = self.recv_incoming.recv().await?;

        Ok((message, source))
    }

    pub fn local_endpoint(&self) -> AnonEndpoint {
        self.endpoint
    }
}

#[tracing::instrument(skip(ctx))]
pub async fn n2r_socket_shuttle(ctx: DaemonContext) -> anyhow::Result<()> {
    async {
        loop {
            let (msg_body, src_relay_ep, dst_anon_ep) = n2r::read_backward(&ctx).await?;
            tracing::debug!(
                src_relay_ep = debug(src_relay_ep),
                dst_anon_ep = debug(dst_anon_ep),
                "shuttling a backward msg"
            );
            queues::fwd_to_client_queue(&ctx, msg_body, src_relay_ep, dst_anon_ep)?;
        }
    }
    .race(async {
        loop {
            let (msg_body, src_anon_ep, dst_dock) = n2r::read_forward(&ctx).await?;
            tracing::debug!(
                src_anon_ep = debug(src_anon_ep),
                dst_dock = debug(dst_dock),
                "shuttling a forward msg"
            );
            queues::fwd_to_relay_queue(&ctx, msg_body, src_anon_ep, dst_dock)?;
        }
    })
    .await
}
