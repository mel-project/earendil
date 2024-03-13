use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use bytes::Bytes;
use clone_macro::clone;
use concurrent_queue::ConcurrentQueue;
use earendil_crypt::{AnonRemote, RelayFingerprint, RemoteId};
use earendil_packet::{Dock, Message};
use futures_util::TryFutureExt;
use rand::Rng;

use smol::channel::{Receiver, Sender};
use smolscale::immortal::{Immortal, RespawnStrategy};

use crate::{
    daemon::context::{
        n2r_reply, n2r_send, DaemonContext, ANON_IDENTITIES, CLIENT_SOCKET_RECV_QUEUES,
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
    recv_incoming: Receiver<(Message, RemoteId)>, // relays can only ever receive communication from clients
}

impl N2rRelaySocket {
    pub fn bind(ctx: DaemonContext, dock: Option<Dock>) -> Self {
        let my_pk = ctx
            .get(GLOBAL_IDENTITY)
            .expect("only relays have global identities")
            .public();
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

        N2rRelaySocket {
            bound_dock,
            recv_incoming,
        }
    }

    pub async fn send_to(
        &self,
        body: Bytes,
        endpoint: AnonEndpoint,
    ) -> Result<(), SocketSendError> {
        n2r_reply(
            &self.bound_dock.ctx,
            self.bound_dock.dock,
            endpoint.anon_dest,
            endpoint.dock,
            body,
        )
        .await?;
        Ok(())
    }

    pub async fn recv_from(&self) -> Result<(Bytes, AnonEndpoint), SocketRecvError> {
        let (message, source) = self.recv_incoming.recv().await.map_err(|e| {
            tracing::debug!("N2rSocket RecvError: {e}");
            SocketRecvError::N2rRecvError
        })?;

        match source {
            RemoteId::Anon(anon_dest) => {
                let endpoint = AnonEndpoint::new(anon_dest, message.source_dock);
                Ok((message.body.clone(), endpoint))
            }
            _ => Err(SocketRecvError::N2rRecvError),
        }
    }

    pub fn local_endpoint(&self) -> RelayEndpoint {
        RelayEndpoint::new(self.bound_dock.fp, self.bound_dock.dock)
    }
}

struct ClientBoundDock {
    anon_id: AnonRemote,
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
    recv_incoming: Receiver<(Message, RemoteId)>, // relays can only ever receive communication from clients
}

impl N2rClientSocket {
    pub fn bind(ctx: DaemonContext, dock: Option<Dock>) -> Self {
        let my_anon_id = AnonRemote::new();
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

        N2rClientSocket {
            bound_dock,
            recv_incoming,
        }
    }

    pub async fn send_to(
        &self,
        body: Bytes,
        endpoint: RelayEndpoint,
    ) -> Result<(), SocketSendError> {
        n2r_send(
            &self.bound_dock.ctx,
            self.bound_dock.anon_id,
            self.bound_dock.dock,
            endpoint.fingerprint,
            endpoint.dock,
            body,
        )
        .await?;
        Ok(())
    }

    pub async fn recv_from(&self) -> Result<(Bytes, RelayEndpoint), SocketRecvError> {
        let (message, source) = self.recv_incoming.recv().await.map_err(|e| {
            tracing::debug!("N2rSocket RecvError: {e}");
            SocketRecvError::N2rRecvError
        })?;

        match source {
            RemoteId::Relay(fp) => {
                let endpoint = RelayEndpoint::new(fp, message.source_dock);
                Ok((message.body, endpoint))
            }
            _ => Err(SocketRecvError::N2rRecvError),
        }
    }

    pub fn local_endpoint(&self) -> AnonEndpoint {
        AnonEndpoint::new(self.bound_dock.anon_id, self.bound_dock.dock)
    }
}
