use bytes::Bytes;
use earendil_crypt::{Fingerprint, IdentitySecret};
use earendil_packet::Dock;

use super::{
    haven_socket::HavenSocket,
    n2r_socket::{Endpoint, N2rSocket},
    DaemonContext,
};

pub struct Socket {
    ctx: DaemonContext,
    inner: InnerSocket,
}

impl Socket {
    pub fn bind_haven(
        ctx: DaemonContext,
        identity_sk: Option<IdentitySecret>,
        dock: Option<Dock>,
        rendezvous_point: Option<Fingerprint>,
    ) -> Socket {
        let inner = InnerSocket::Haven(HavenSocket::bind(
            ctx.clone(),
            identity_sk,
            dock,
            rendezvous_point,
        ));

        Self { ctx, inner }
    }

    pub fn bind_n2r(
        ctx: DaemonContext,
        anon_id: Option<IdentitySecret>,
        dock: Option<Dock>,
    ) -> Socket {
        let inner = InnerSocket::N2R(N2rSocket::bind(ctx.clone(), anon_id, dock));
        Self { ctx, inner }
    }

    pub async fn send_to(&self, body: Bytes, endpoint: Endpoint) -> anyhow::Result<()> {
        match &self.inner {
            InnerSocket::N2R(s) => s.send_to(body, endpoint).await,
            InnerSocket::Haven(s) => s.send_to(body, endpoint).await,
        }
    }

    pub async fn recv_from(&self) -> anyhow::Result<(Bytes, Endpoint)> {
        match &self.inner {
            InnerSocket::N2R(s) => s.recv_from().await,
            InnerSocket::Haven(s) => s.recv_from().await,
        }
    }
}

enum InnerSocket {
    Haven(HavenSocket),
    N2R(N2rSocket),
}
