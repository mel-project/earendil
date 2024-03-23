mod listen;
mod visitor;
mod vrh;

use std::sync::atomic::{AtomicU64, Ordering};

use crate::socket::n2r_socket::N2rClientSocket;
use crate::socket::HavenEndpoint;
use crate::socket::RelayEndpoint;
use crate::{context::DaemonContext, dht::dht_get};
use anyhow::Context as _;
use bytes::Bytes;
use earendil_crypt::AnonEndpoint;
use earendil_crypt::{HavenIdentitySecret, RelayFingerprint};
use earendil_packet::crypt::AeadKey;
use earendil_packet::crypt::DhSecret;
use serde::Deserialize;
use serde::Serialize;
use smol::{
    channel::{Receiver, Sender},
    Task,
};
use stdcode::StdcodeSerializeExt;
use tap::Tap;

use self::{
    listen::listen_loop,
    visitor::visitor_loop,
    vrh::{HavenHandshake, HavenMsg, V2rMessage, VisitorHandshake},
};

const HAVEN_FORWARD_DOCK: u32 = 100002;

const HAVEN_UP: &[u8] = b"haven-up";
const HAVEN_DN: &[u8] = b"haven-dn";

pub struct HavenListener {
    _listen_task: Task<anyhow::Result<()>>,
    // channel for putting all incoming ClientHandshakes
    recv_accepted: Receiver<HavenConnection>,
}

impl HavenListener {
    pub async fn bind(
        ctx: &DaemonContext,
        identity: HavenIdentitySecret,
        port: u16,
        rendezvous: RelayFingerprint,
    ) -> anyhow::Result<Self> {
        let (send_accepted, recv_accepted) = smol::channel::bounded(100);
        let _listen_task = smolscale::spawn(listen_loop(
            ctx.clone(),
            identity,
            port,
            rendezvous,
            send_accepted,
        ));
        Ok(Self {
            _listen_task,
            recv_accepted,
        })
    }

    pub async fn accept(&self) -> anyhow::Result<HavenConnection> {
        Ok(self.recv_accepted.recv().await?)
    }
}

pub struct HavenConnection {
    // encryption state for this connection
    enc_key: AeadKey,
    enc_nonce: AtomicU64,
    dec_key: AeadKey,
    dec_nonce: AtomicU64,
    // some way of sending packets to the other side (e.g. the sending end of a channel, or a boxed closure)
    // some way of receiving packets from the other side (e.g. the receiving end of a channel, or a boxed closure)
    // these channels are provided by whoever constructs this connection:
    // - for connect(), they should connect to tasks that shuffle packets to/from the rendezvous
    // - for the haven side, it's a bit more complex. the haven listener should spawn some task that manages a table of channels, similar to how we currently manage a table of encrypters. this task should go through all incoming packets, finishing encryption handshakes, and constructing HavenConnections by filling in its fields with the correct encryption state as well as the right packet-sending and packet-receiving functionality.
    send_upstream: Sender<Bytes>,
    recv_downstream: Receiver<Bytes>,

    _task: Task<anyhow::Result<()>>,
}

impl HavenConnection {
    /// Establish a connection to the given haven endpoint.
    pub async fn connect(ctx: &DaemonContext, dest_haven: HavenEndpoint) -> anyhow::Result<Self> {
        let n2r_skt = N2rClientSocket::bind(ctx.clone(), AnonEndpoint::new())?;
        // lookup the haven info using the dht
        let locator = dht_get(ctx, dest_haven.fingerprint, &n2r_skt)
            .await
            .context("dht_get failed")?
            .context("haven not found in DHT")?;
        let rendezvous_ep = RelayEndpoint::new(locator.rendezvous_point, HAVEN_FORWARD_DOCK);

        // do the handshake to the other side over N2R
        let my_esk = DhSecret::generate();
        let handshake = V2rMessage {
            dest_haven,
            payload: HavenMsg::VisitorHs(VisitorHandshake(my_esk.public())),
        };
        n2r_skt
            .send_to(handshake.stdcode().into(), rendezvous_ep)
            .await?;
        // they sign their ephemeral public key
        let server_hs: HavenHandshake = stdcode::deserialize(&n2r_skt.recv_from().await?.0)?;
        server_hs
            .id_pk
            .verify(server_hs.eph_pk.as_bytes(), &server_hs.sig)?;
        if server_hs.id_pk.fingerprint() != dest_haven.fingerprint {
            anyhow::bail!("haven public key verification failed")
        }

        let shared_sec = my_esk.shared_secret(&server_hs.eph_pk);
        let up_key = AeadKey::from_bytes(
            blake3::keyed_hash(blake3::hash(HAVEN_UP).as_bytes(), &shared_sec).as_bytes(),
        );
        let down_key = AeadKey::from_bytes(
            blake3::keyed_hash(blake3::hash(HAVEN_DN).as_bytes(), &shared_sec).as_bytes(),
        );

        let (send_upstream, recv_upstream) = smol::channel::bounded(1);
        let (send_downstream, recv_downstream) = smol::channel::bounded(1);

        // construct the connection
        Ok(HavenConnection {
            enc_key: up_key,
            enc_nonce: AtomicU64::new(0),
            dec_key: down_key,
            dec_nonce: AtomicU64::new(0),
            send_upstream,
            recv_downstream,

            _task: smolscale::spawn(visitor_loop(
                ctx.clone(),
                send_downstream,
                recv_upstream,
                locator.rendezvous_point,
                dest_haven,
            )),
        })
    }

    pub async fn send(&self, bts: &[u8]) -> anyhow::Result<()> {
        let nonce = [0; 12].tap_mut(|b| {
            b[..8].copy_from_slice(&self.enc_nonce.fetch_add(1, Ordering::SeqCst).to_le_bytes())
        });
        let ctext = self.enc_key.seal(&nonce, bts);
        self.send_upstream.send(ctext.into()).await?;
        Ok(())
    }

    pub async fn recv(&self) -> anyhow::Result<Bytes> {
        let ctext = self.recv_downstream.recv().await?;
        let nonce = [0; 12].tap_mut(|b| {
            b[..8].copy_from_slice(&self.dec_nonce.fetch_add(1, Ordering::SeqCst).to_le_bytes())
        });
        let ptext = self.dec_key.open(&nonce, &ctext)?;
        Ok(ptext.into())
    }
}
