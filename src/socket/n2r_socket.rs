use std::sync::Arc;

use bytes::Bytes;

use earendil_crypt::{AnonRemote, RemoteId};
use earendil_packet::{Dock, Message};
use rand::Rng;

use smol::channel::Receiver;

use crate::{
    context::{DaemonContext, GLOBAL_IDENTITY},
    n2r,
    socket::SocketRecvError,
};

use super::{
    queues::{new_client_queue, new_relay_queue, QueueReceiver},
    AnonEndpoint, RelayEndpoint,
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
        let my_pk = ctx
            .get(GLOBAL_IDENTITY)
            .expect("only relays have global identities")
            .public();
        let my_fp = my_pk.fingerprint();
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
        n2r::send_backward(
            &self.ctx,
            self.dock,
            endpoint.anon_dest,
            endpoint.dock,
            body,
        )
        .await?;
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
                .get(GLOBAL_IDENTITY)
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
    pub fn bind(ctx: DaemonContext, dock: Option<Dock>) -> anyhow::Result<Self> {
        let my_anon_id = AnonRemote::new();
        let (dock, recv_incoming) = if let Some(dock) = dock {
            (
                dock,
                new_client_queue(&ctx, AnonEndpoint::new(my_anon_id, dock))?,
            )
        } else {
            loop {
                let dock = rand::random();
                if let Ok(val) = new_client_queue(&ctx, AnonEndpoint::new(my_anon_id, dock)) {
                    break (dock, val);
                }
            }
        };

        Ok(N2rClientSocket {
            ctx,
            endpoint: AnonEndpoint::new(my_anon_id, dock),
            recv_incoming: Arc::new(recv_incoming),
        })
    }

    pub async fn send_to(&self, body: Bytes, endpoint: RelayEndpoint) -> anyhow::Result<()> {
        n2r::send_forward(
            &self.ctx,
            self.endpoint.anon_dest,
            self.endpoint.dock,
            endpoint.fingerprint,
            endpoint.dock,
            body,
        )
        .await?;
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
