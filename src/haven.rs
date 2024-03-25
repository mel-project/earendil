mod listen;
mod visitor;
mod vrh;

use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{context::DaemonContext, dht::dht_get};
use crate::{global_rpc::server::REGISTERED_HAVENS, n2r_socket::N2rClientSocket};
use crate::{haven::vrh::H2rMessage, n2r_socket::RelayEndpoint};
use crate::{haven::vrh::R2hMessage, n2r_socket::N2rRelaySocket};
use anyhow::Context as _;
use bytes::Bytes;
use earendil_crypt::{AnonEndpoint, HavenFingerprint, HavenIdentityPublic};
use earendil_crypt::{HavenIdentitySecret, RelayFingerprint};
use earendil_packet::crypt::DhSecret;
use earendil_packet::crypt::{AeadKey, DhPublic};

use futures::TryFutureExt;
use serde::{Deserialize, Serialize};
use smol::{
    channel::{Receiver, Sender},
    Task,
};
use stdcode::StdcodeSerializeExt;
use tap::Tap;
use tracing::instrument;

use self::{
    listen::listen_loop,
    visitor::visitor_loop,
    vrh::{HavenMsg, V2rMessage, VisitorHandshake},
};

#[derive(Copy, Clone, Deserialize, Serialize, Hash, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub struct HavenEndpoint {
    pub fingerprint: HavenFingerprint,
    pub port: u16,
}

impl HavenEndpoint {
    pub fn new(fingerprint: HavenFingerprint, port: u16) -> Self {
        Self { fingerprint, port }
    }
}

impl Display for HavenEndpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.fingerprint, self.port)
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
        let port = u16::from_str(parts[1])?;
        Ok(HavenEndpoint::new(fingerprint, port))
    }
}

const HAVEN_FORWARD_DOCK: u32 = 100002;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HavenLocator {
    pub identity_pk: HavenIdentityPublic,
    pub onion_pk: DhPublic,
    pub rendezvous_point: RelayFingerprint,
    pub signature: Bytes,
}

impl HavenLocator {
    pub fn new(
        identity_sk: HavenIdentitySecret,
        onion_pk: DhPublic,
        rendezvous_fingerprint: RelayFingerprint,
    ) -> HavenLocator {
        let identity_pk = identity_sk.public();
        let locator = HavenLocator {
            identity_pk,
            onion_pk,
            rendezvous_point: rendezvous_fingerprint,
            signature: Bytes::new(),
        };
        let signature = identity_sk.sign(&locator.to_sign());

        HavenLocator {
            identity_pk,
            onion_pk,
            rendezvous_point: rendezvous_fingerprint,
            signature,
        }
    }

    pub fn to_sign(&self) -> [u8; 32] {
        let locator = HavenLocator {
            identity_pk: self.identity_pk,
            onion_pk: self.onion_pk,
            rendezvous_point: self.rendezvous_point,
            signature: Bytes::new(),
        };
        let hash = blake3::keyed_hash(b"haven_locator___________________", &locator.stdcode());

        *hash.as_bytes()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterHavenReq {
    pub anon_id: AnonEndpoint,
    pub identity_pk: HavenIdentityPublic,
    pub port: u16,
    pub sig: Bytes,
    pub unix_timestamp: u64,
}

impl RegisterHavenReq {
    pub fn new(my_anon_id: AnonEndpoint, identity_sk: HavenIdentitySecret, port: u16) -> Self {
        let mut reg = Self {
            anon_id: my_anon_id,
            identity_pk: identity_sk.public(),
            port,
            sig: Bytes::new(),
            unix_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        reg.sig = identity_sk.sign(reg.to_sign().as_bytes());
        reg
    }

    pub fn to_sign(&self) -> blake3::Hash {
        let mut this = self.clone();
        this.sig = Bytes::new();
        blake3::keyed_hash(b"haven_registration______________", &this.stdcode())
    }
}

const HAVEN_UP: &[u8] = b"haven-up";
const HAVEN_DN: &[u8] = b"haven-dn";

/// Represents a running haven, able to accept incoming [HavenPacketConn]s.
pub struct HavenListener {
    _listen_task: Task<anyhow::Result<()>>,
    recv_accepted: Receiver<HavenPacketConn>,
}

impl HavenListener {
    /// Binds a new haven. The rendezvous must be specified.
    pub async fn bind(
        ctx: &DaemonContext,
        identity: HavenIdentitySecret,
        port: u16,
        rendezvous: RelayFingerprint,
    ) -> anyhow::Result<Self> {
        let (send_accepted, recv_accepted) = smol::channel::bounded(100);
        let _listen_task = smolscale::spawn(
            listen_loop(ctx.clone(), identity, port, rendezvous, send_accepted)
                .inspect_err(|e| tracing::warn!(err = debug(e), "haven listener loop died")),
        );
        Ok(Self {
            _listen_task,
            recv_accepted,
        })
    }

    /// Accepts a new unreliable connection. Wrap in a [Stream] or similar if reliability is required.
    pub async fn accept(&self) -> anyhow::Result<HavenPacketConn> {
        Ok(self.recv_accepted.recv().await?)
    }
}

/// A low-level, best-effort visitor-haven connection.
pub struct HavenPacketConn {
    // encryption state for this connection
    enc_key: AeadKey,
    enc_nonce: AtomicU64,
    dec_key: AeadKey,

    // some way of sending packets to the other side (e.g. the sending end of a channel, or a boxed closure)
    // some way of receiving packets from the other side (e.g. the receiving end of a channel, or a boxed closure)
    // these channels are provided by whoever constructs this connection:
    // - for connect(), they should connect to tasks that shuffle packets to/from the rendezvous
    // - for the haven side, it's a bit more complex. the haven listener should spawn some task that manages a table of channels, similar to how we currently manage a table of encrypters. this task should go through all incoming packets, finishing encryption handshakes, and constructing HavenConnections by filling in its fields with the correct encryption state as well as the right packet-sending and packet-receiving functionality.
    send_upstream: Sender<Bytes>,
    recv_downstream: Receiver<Bytes>,

    _task: Task<anyhow::Result<()>>,
}

impl HavenPacketConn {
    /// Establish a connection to the given haven endpoint.
    pub async fn connect(ctx: &DaemonContext, dest_haven: HavenEndpoint) -> anyhow::Result<Self> {
        // lookup the haven info using the dht
        let locator = dht_get(
            ctx,
            dest_haven.fingerprint,
            &N2rClientSocket::bind(ctx.clone(), AnonEndpoint::new())?,
        )
        .await
        .context("dht_get failed")?
        .context("haven not found in DHT")?;

        let n2r_skt = N2rClientSocket::bind(ctx.clone(), AnonEndpoint::new())?;
        let rendezvous_ep = RelayEndpoint::new(locator.rendezvous_point, HAVEN_FORWARD_DOCK);

        // do the handshake to the other side over N2R
        let my_esk = DhSecret::generate();
        let my_hs = V2rMessage {
            dest_haven,
            payload: HavenMsg::VisitorHs(VisitorHandshake(my_esk.public())),
        };
        n2r_skt
            .send_to(my_hs.stdcode().into(), rendezvous_ep)
            .await?;
        // they sign their ephemeral public key
        let (their_hs, addr) = n2r_skt.recv_from().await?;
        tracing::debug!(
            their_hs_len = their_hs.len(),
            addr = debug(addr),
            my_endpoint = debug(n2r_skt.local_endpoint()),
            "received their_hs"
        );
        let their_hs: HavenMsg =
            stdcode::deserialize(&their_hs).context("deserialization of haven handshake failed")?;
        let their_hs = match their_hs {
            HavenMsg::HavenHs(server_hs) => server_hs,
            x => anyhow::bail!(
                "haven sent us something other than a haven handshake: {:?}",
                x
            ),
        };
        their_hs
            .id_pk
            .verify(their_hs.eph_pk.as_bytes(), &their_hs.sig)?;
        if their_hs.id_pk.fingerprint() != dest_haven.fingerprint {
            anyhow::bail!("haven public key verification failed")
        }

        let shared_sec = my_esk.shared_secret(&their_hs.eph_pk);
        let up_key = AeadKey::from_bytes(
            blake3::keyed_hash(blake3::hash(HAVEN_UP).as_bytes(), &shared_sec).as_bytes(),
        );
        let down_key = AeadKey::from_bytes(
            blake3::keyed_hash(blake3::hash(HAVEN_DN).as_bytes(), &shared_sec).as_bytes(),
        );

        let (send_upstream, recv_upstream) = smol::channel::bounded(1);
        let (send_downstream, recv_downstream) = smol::channel::bounded(1);

        // construct the connection
        Ok(HavenPacketConn {
            enc_key: up_key,
            enc_nonce: AtomicU64::new(0),
            dec_key: down_key,

            send_upstream,
            recv_downstream,

            _task: smolscale::spawn(visitor_loop(
                send_downstream,
                recv_upstream,
                locator.rendezvous_point,
                dest_haven,
                n2r_skt,
            )),
        })
    }

    /// Sends a packet to the other side. It may or may not get there, since the connection is best-effort.
    pub async fn send_pkt(&self, bts: &[u8]) -> anyhow::Result<()> {
        let nonce = self.enc_nonce.fetch_add(1, Ordering::SeqCst);
        let nonce_bts = [0; 12].tap_mut(|b| b[..8].copy_from_slice(&nonce.to_le_bytes()));
        let ctext = self.enc_key.seal(&nonce_bts, bts);
        self.send_upstream
            .send((nonce, ctext).stdcode().into())
            .await?;
        Ok(())
    }

    /// Receives a packet from the other side. We may not receive all the packets sent, since the connection is best-effort.
    pub async fn recv_pkt(&self) -> anyhow::Result<Bytes> {
        let ctext = self.recv_downstream.recv().await?;
        let (nonce, ctext): (u64, Vec<u8>) = stdcode::deserialize(&ctext)?;
        // TODO TODO replay protection by preventing the nonce from repeating
        let nonce_bts = [0; 12].tap_mut(|b| b[..8].copy_from_slice(&nonce.to_le_bytes()));
        let ptext = self.dec_key.open(&nonce_bts, &ctext)?;
        Ok(ptext.into())
    }
}

#[instrument(skip(ctx))]
/// Loop that listens to and handles incoming haven forwarding requests
pub async fn rendezvous_forward_loop(ctx: DaemonContext) -> anyhow::Result<()> {
    let socket = N2rRelaySocket::bind(ctx.clone(), Some(HAVEN_FORWARD_DOCK))?;

    loop {
        if let Ok((msg, src_ep)) = socket.recv_from().await {
            let ctx = ctx.clone();
            let src_is_visitor = ctx.get(REGISTERED_HAVENS).get_by_key(&src_ep).is_none();
            if src_is_visitor {
                let inner: V2rMessage = stdcode::deserialize(&msg)?;

                if let Some(haven_anon_ep) = ctx
                    .get(REGISTERED_HAVENS)
                    .get_by_value(&inner.dest_haven.fingerprint)
                {
                    tracing::debug!(
                        src_ep = debug(src_ep),
                        haven_anon_ep = debug(haven_anon_ep),
                        "received V2R msg"
                    );

                    let body: Bytes = R2hMessage {
                        src_visitor: src_ep,

                        payload: inner.payload,
                    }
                    .stdcode()
                    .into();

                    tracing::debug!(haven_anon_ep = debug(haven_anon_ep), "sending R2H");
                    socket.send_to(body, haven_anon_ep).await?;
                } else {
                    tracing::warn!(
                        "haven {} is not registered with me!",
                        inner.dest_haven.fingerprint
                    );
                }
            } else {
                // src is haven
                let inner: H2rMessage = stdcode::deserialize(&msg)?;
                tracing::debug!(
                    src_ep = debug(src_ep),
                    dest_visitor = debug(inner.dest_visitor),
                    "received H2R msg",
                );
                let body: Bytes = inner.payload.stdcode().into();
                tracing::debug!(dest_visitor = debug(inner.dest_visitor), "sending bare");
                socket.send_to(body, inner.dest_visitor).await?;
            }
        };
    }
}
