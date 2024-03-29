use std::{fmt::Display, str::FromStr};

use bytes::Bytes;
use earendil_crypt::{Fingerprint, IdentitySecret};
use earendil_packet::Dock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    control_protocol::SendMessageError,
    daemon::{context::DaemonContext, Daemon},
};

use self::{haven_socket::HavenSocket, n2r_socket::N2rSocket};

pub(crate) mod crypt_session;
pub(crate) mod haven_socket;
pub(crate) mod n2r_socket;

pub struct Socket {
    inner: InnerSocket,
}

impl Socket {
    pub fn bind_haven(
        daemon: &Daemon,
        isk: IdentitySecret,
        dock: Option<Dock>,
        rendezvous_point: Option<Fingerprint>,
    ) -> Socket {
        let inner = HavenSocket::bind(daemon.ctx.clone(), isk, dock, rendezvous_point);
        Self {
            inner: InnerSocket::Haven(inner),
        }
    }

    pub fn bind_n2r(daemon: &Daemon, isk: IdentitySecret, dock: Option<Dock>) -> Socket {
        let inner = N2rSocket::bind(daemon.ctx.clone(), isk, dock);
        Self {
            inner: InnerSocket::N2r(inner),
        }
    }

    pub(crate) fn bind_haven_internal(
        ctx: DaemonContext,
        isk: IdentitySecret,
        dock: Option<Dock>,
        rendezvous_point: Option<Fingerprint>,
    ) -> Socket {
        let inner = InnerSocket::Haven(HavenSocket::bind(ctx.clone(), isk, dock, rendezvous_point));

        Self { inner }
    }

    pub(crate) fn bind_n2r_internal(
        ctx: DaemonContext,
        isk: IdentitySecret,
        dock: Option<Dock>,
    ) -> Socket {
        let inner = InnerSocket::N2r(N2rSocket::bind(ctx.clone(), isk, dock));
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

    pub fn local_endpoint(&self) -> Endpoint {
        match &self.inner {
            InnerSocket::Haven(haven_skt) => haven_skt.local_endpoint(),
            InnerSocket::N2r(n2r_skt) => n2r_skt.local_endpoint(),
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
    N2rSendError(#[from] SendMessageError),
    #[error("haven encryption problem: {0}")]
    HavenEncryptionError(String),
}

#[derive(Error, Serialize, Deserialize, Debug)]
pub enum SocketRecvError {
    #[error("error receiving in n2r_socket")]
    N2rRecvError,
}

#[derive(Copy, Clone, Deserialize, Serialize, Hash, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub struct Endpoint {
    pub fingerprint: Fingerprint,
    pub dock: Dock,
}

impl Endpoint {
    pub fn new(fingerprint: Fingerprint, dock: Dock) -> Endpoint {
        Endpoint { fingerprint, dock }
    }
}

impl Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:{}", self.fingerprint, self.dock)
    }
}

impl FromStr for Endpoint {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let elems: Vec<&str> = s.split(':').collect();
        if elems.len() != 2 {
            return Err(anyhow::anyhow!(
                "Wrong endpoint format! Endpoint format should be fingerprint:dock"
            ));
        }
        let fp = Fingerprint::from_str(elems[0])?;
        let dock = u32::from_str(elems[1])?;
        Ok(Endpoint::new(fp, dock))
    }
}
