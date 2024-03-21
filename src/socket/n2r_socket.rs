use std::sync::Arc;

use anyhow::Context;
use bytes::Bytes;

use earendil_crypt::AnonEndpoint;
use earendil_packet::Dock;

use crate::{
    context::{DaemonContext, MY_RELAY_IDENTITY},
    n2r,
    socket::SocketRecvError,
};

use super::{
    queues::{new_client_queue, new_relay_queue, QueueReceiver},
    RelayEndpoint,
};

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
        let (message, source) = self.recv_incoming.recv().await.map_err(|e| {
            tracing::debug!("N2rSocket RecvError: {e}");
            SocketRecvError::N2rRecvError
        })?;

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
    pub fn bind(ctx: DaemonContext) -> anyhow::Result<Self> {
        let my_anon_id = AnonEndpoint::new();
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

    pub async fn recv_from(&self) -> anyhow::Result<(Bytes, RelayEndpoint)> {
        let (message, source) = self.recv_incoming.recv().await.map_err(|e| {
            tracing::debug!("N2rSocket RecvError: {e}");
            SocketRecvError::N2rRecvError
        })?;

        Ok((message, source))
    }

    pub fn local_endpoint(&self) -> AnonEndpoint {
        self.endpoint
    }
}
