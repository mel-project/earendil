use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use bytes::Bytes;
use earendil_crypt::{AnonRemote, HavenFingerprint, HavenIdentitySecret, RelayFingerprint};
use earendil_packet::Dock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{context::DaemonContext, control_protocol::SendMessageError, daemon::Daemon};

use self::{
    haven_socket::HavenSocket,
    n2r_socket::{N2rClientSocket, N2rRelaySocket},
};

pub(crate) mod crypt_session;
pub(crate) mod haven_socket;
pub(crate) mod n2r_socket;

pub struct Socket {
    inner: InnerSocket,
}

impl Socket {
    pub async fn bind_haven(
        daemon: &Daemon,
        isk: HavenIdentitySecret,
        dock: Option<Dock>,
        rendezvous_point: Option<RelayFingerprint>,
    ) -> Socket {
        let inner = HavenSocket::bind(daemon.ctx.clone(), isk, dock, rendezvous_point);
        Self {
            inner: InnerSocket::Haven(inner),
        }
    }

    pub async fn bind_n2r_client(daemon: &Daemon, dock: Option<Dock>) -> Socket {
        let inner = N2rClientSocket::bind(daemon.ctx.clone(), dock);
        Self {
            inner: InnerSocket::N2rClient(inner),
        }
    }

    pub fn bind_n2r_relay(daemon: &Daemon, dock: Option<Dock>) -> Socket {
        let inner = N2rRelaySocket::bind(daemon.ctx.clone(), dock);
        Self {
            inner: InnerSocket::N2rRelay(inner),
        }
    }

    pub(crate) fn bind_haven_internal(
        ctx: DaemonContext,
        isk: HavenIdentitySecret,
        dock: Option<Dock>,
        rendezvous_point: Option<RelayFingerprint>,
    ) -> Socket {
        let inner = InnerSocket::Haven(HavenSocket::bind(ctx.clone(), isk, dock, rendezvous_point));

        Self { inner }
    }

    pub(crate) fn bind_n2r_client_internal(ctx: DaemonContext, dock: Option<Dock>) -> Socket {
        let inner = InnerSocket::N2rClient(N2rClientSocket::bind(ctx.clone(), dock));
        Self { inner }
    }

    pub(crate) fn bind_n2r_relay_internal(ctx: DaemonContext, dock: Option<Dock>) -> Socket {
        let inner = InnerSocket::N2rRelay(N2rRelaySocket::bind(ctx.clone(), dock));
        Self { inner }
    }

    pub async fn send_to(&self, body: Bytes, endpoint: Endpoint) -> anyhow::Result<()> {
        match &self.inner {
            InnerSocket::N2rRelay(s) => {
                if let Endpoint::Anon(ep) = endpoint {
                    s.send_to(body, ep).await
                } else {
                    anyhow::bail!("relay sockets can only send messages to client sockets");
                }
            }
            InnerSocket::Haven(s) => {
                if let Endpoint::Haven(ep) = endpoint {
                    s.send_to(body, ep).await
                } else {
                    anyhow::bail!("haven sockets can only send haven messages to haven sockets");
                }
            }
            InnerSocket::N2rClient(s) => {
                if let Endpoint::Relay(ep) = endpoint {
                    s.send_to(body, ep).await
                } else {
                    anyhow::bail!("client sockets can only send messages to server sockets");
                }
            }
        }
    }

    pub async fn recv_from(&self) -> Result<(Bytes, Endpoint), SocketRecvError> {
        match &self.inner {
            InnerSocket::N2rRelay(s) => {
                let (b, ep) = s.recv_from().await?;
                Ok((b, Endpoint::Anon(ep)))
            }
            InnerSocket::Haven(s) => {
                let (b, ep) = s.recv_from().await?;
                Ok((b, Endpoint::Haven(ep)))
            }
            InnerSocket::N2rClient(s) => {
                let (b, ep) = s.recv_from().await?;
                Ok((b, Endpoint::Relay(ep)))
            }
        }
    }

    pub fn local_endpoint(&self) -> Endpoint {
        match &self.inner {
            InnerSocket::N2rClient(s) => Endpoint::Anon(s.local_endpoint()),
            InnerSocket::N2rRelay(s) => Endpoint::Relay(s.local_endpoint()),
            InnerSocket::Haven(s) => Endpoint::Haven(s.local_endpoint()),
        }
    }
}

enum InnerSocket {
    Haven(HavenSocket),
    N2rClient(N2rClientSocket),
    N2rRelay(N2rRelaySocket),
}

#[derive(Error, Serialize, Deserialize, Debug)]
pub enum SocketSendError {
    #[error(transparent)]
    N2rSendError(#[from] SendMessageError),
    #[error("haven encryption problem: {0}")]
    HavenEncryptionError(String),
    #[error("mismatched sockets: {0}")]
    MismatchedSockets(String),
}

#[derive(Error, Serialize, Deserialize, Debug)]
pub enum SocketRecvError {
    #[error("error receiving in n2r_socket")]
    N2rRecvError,
    #[error("mismatched sockets: {0}")]
    MismatchedSockets(String),
}

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

#[derive(Copy, Clone, Deserialize, Serialize, Hash, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub struct HavenEndpoint {
    pub fingerprint: HavenFingerprint,
    pub dock: Dock,
}

impl HavenEndpoint {
    pub fn new(fingerprint: HavenFingerprint, dock: Dock) -> Self {
        Self { fingerprint, dock }
    }
}

impl Display for HavenEndpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.fingerprint, self.dock)
    }
}

impl FromStr for HavenEndpoint {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("invalid haven endpoint format"));
        }
        let fingerprint = HavenFingerprint::from_str(parts[0])?;
        let dock = Dock::from_str(parts[1])?;
        Ok(HavenEndpoint::new(fingerprint, dock))
    }
}

#[derive(Copy, Clone, Deserialize, Serialize, Hash, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub struct AnonEndpoint {
    pub anon_dest: AnonRemote,
    pub dock: Dock,
}

impl AnonEndpoint {
    pub fn new(anon_dest: AnonRemote, dock: Dock) -> Self {
        Self { anon_dest, dock }
    }
}

impl Display for AnonEndpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.anon_dest, self.dock)
    }
}

impl FromStr for AnonEndpoint {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("invalid anon endpoint format"));
        }
        let fp_bytes: [u8; 16] = parts[0].as_bytes().try_into()?;
        let fingerprint = AnonRemote(fp_bytes);
        let dock = Dock::from_str(parts[1])?;
        Ok(AnonEndpoint::new(fingerprint, dock))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Endpoint {
    Relay(RelayEndpoint),
    Anon(AnonEndpoint),
    Haven(HavenEndpoint),
}

impl Display for Endpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Endpoint::Relay(ep) => write!(f, "{}:{}", ep.fingerprint, ep.dock),
            Endpoint::Anon(ep) => write!(f, "{}:{}", ep.anon_dest, ep.dock),
            Endpoint::Haven(ep) => write!(f, "{}:{}", ep.fingerprint, ep.dock),
        }
    }
}
