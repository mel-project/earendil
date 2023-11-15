use bytes::Bytes;
use earendil_crypt::{Fingerprint, IdentitySecret};
use earendil_packet::Dock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::control_protocol::SendMessageError;

use super::{
    haven_socket::HavenSocket,
    n2r_socket::{Endpoint, N2rSocket},
    DaemonContext,
};

pub struct Socket {
    inner: InnerSocket,
}

impl Socket {
    pub fn bind_haven(
        ctx: &DaemonContext,
        anon_id: Option<IdentitySecret>,
        dock: Option<Dock>,
        rendezvous_point: Option<Fingerprint>,
    ) -> Socket {
        let inner = InnerSocket::Haven(HavenSocket::bind(
            ctx.clone(),
            anon_id,
            dock,
            rendezvous_point,
        ));

        Self { inner }
    }

    pub fn bind_n2r(
        ctx: &DaemonContext,
        anon_id: Option<IdentitySecret>,
        dock: Option<Dock>,
    ) -> Socket {
        let inner = InnerSocket::N2r(N2rSocket::bind(ctx.clone(), anon_id, dock));
        Self { inner }
    }

    pub async fn send_to(&self, body: Bytes, endpoint: Endpoint) -> Result<(), SocketSendError> {
        match &self.inner {
            InnerSocket::N2r(s) => s.send_to(body, endpoint).await,
            InnerSocket::Haven(s) => s.send_to(body, endpoint).await,
        }
    }

    pub async fn recv_from(&self) -> Result<(Bytes, Endpoint), SocketRecvError> {
        match &self.inner {
            InnerSocket::N2r(s) => s.recv_from().await,
            InnerSocket::Haven(s) => s.recv_from().await,
        }
    }

    pub fn skt_info(&self) -> Endpoint {
        match &self.inner {
            InnerSocket::Haven(haven_skt) => haven_skt.skt_info(),
            InnerSocket::N2r(n2r_skt) => n2r_skt.skt_info(),
        }
    }
}

enum InnerSocket {
    Haven(HavenSocket),
    N2r(N2rSocket),
}

#[derive(Error, Serialize, Deserialize, Debug)]
pub enum SocketSendError {
    #[error(transparent)]
    N2rSendMessageError(#[from] SendMessageError),
    #[error("could not get rendezvous point from dht")]
    DhtError,
}

#[derive(Error, Serialize, Deserialize, Debug)]
pub enum SocketRecvError {
    #[error("error receiving in n2r_socket")]
    N2rRecvError,
    #[error("improperly formatted inner haven message")]
    HavenMsgBadFormat,
}
