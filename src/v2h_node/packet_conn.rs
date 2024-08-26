mod listen;

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use anyhow::Context;
use bytes::Bytes;
use earendil_crypt::{HavenEndpoint, HavenIdentitySecret, RelayEndpoint, RelayFingerprint};
use earendil_packet::crypt::{AeadKey, DhSecret};

use futures_util::TryFutureExt as _;
use smol::{
    channel::{Receiver, Sender},
    future::FutureExt as _,
    Task,
};
use smol_timeout::TimeoutExt;
use stdcode::StdcodeSerializeExt;
use tap::Tap as _;

use crate::{
    n2r_node::N2rAnonSocket,
    v2h_node::{
        dht::dht_get,
        vrh::{HavenMsg, V2rMessage, VisitorHandshake},
        HAVEN_FORWARD_DOCK,
    },
};

use self::listen::listen_loop;

use super::V2hNodeCtx;

/// A low-level, best-effort visitor-haven connection.
pub struct HavenPacketConn {
    // encryption state for this connection
    enc_key: AeadKey,
    enc_nonce: AtomicU64,
    dec_key: AeadKey,

    // some way of sending packets to the other side
    // some way of receiving packets from the other side
    // these channels are provided by whoever constructs this connection:
    // - for connect(), they should connect to tasks that shuffle packets to/from the rendezvous
    // - for the haven side, it's a bit more complex. the haven listener should spawn some task that manages a table of channels, similar to how we currently manage a table of encrypters. this task should go through all incoming packets, finishing encryption handshakes, and constructing HavenConnections by filling in its fields with the correct encryption state as well as the right packet-sending and packet-receiving functionality.
    send_upstream: Sender<Bytes>,
    recv_downstream: Receiver<Bytes>,

    _task: Task<anyhow::Result<()>>,
}

const HAVEN_UP: &[u8] = b"haven-up";
const HAVEN_DN: &[u8] = b"haven-dn";

impl HavenPacketConn {
    /// Establish a connection to the given haven endpoint.
    pub(super) async fn connect(
        ctx: &V2hNodeCtx,
        dest_haven: HavenEndpoint,
    ) -> anyhow::Result<Self> {
        let n2r_skt = ctx.n2r.bind_anon();

        // lookup the haven info using the dht
        let locator = match dht_get(ctx, dest_haven.fingerprint).await {
            Ok(Some(loc)) => loc,
            Ok(None) => {
                println!("Error: Haven not found in DHT");
                anyhow::bail!("Haven not found in DHT")
            }
            Err(e) => {
                println!("Error: DHT get failed: {}", e);
                return Err(e.context("dht_get failed"));
            }
        };
        tracing::debug!("got haven info from DHT: {:?}", locator);

        let rendezvous_ep = RelayEndpoint::new(locator.rendezvous_point, HAVEN_FORWARD_DOCK);
        tracing::debug!("got n2r_skt: {}", n2r_skt.local_endpoint());
        // do the handshake to the other side over N2R
        let my_esk = DhSecret::generate();
        let my_hs = V2rMessage {
            dest_haven,
            payload: HavenMsg::VisitorHs(VisitorHandshake(my_esk.public())),
        };
        let mut shared_sec: Option<[u8; 32]> = None;
        for i in 0.. {
            n2r_skt
                .send_to(my_hs.stdcode().into(), rendezvous_ep)
                .await?;
            tracing::debug!("sent handshake! i = {i}");
            // they sign their ephemeral public key
            if let Some(Ok((from_haven, addr))) =
                n2r_skt.recv_from().timeout(Duration::from_secs(5)).await
            {
                tracing::debug!(
                    from_haven_len = from_haven.len(),
                    addr = debug(addr),
                    my_endpoint = debug(n2r_skt.local_endpoint()),
                    "received from_haven"
                );
                let haven_msg: HavenMsg = stdcode::deserialize(&from_haven)
                    .context("deserialization of haven handshake failed")?;
                match haven_msg {
                    HavenMsg::HavenHs(server_hs) => {
                        server_hs
                            .id_pk
                            .verify(server_hs.eph_pk.as_bytes(), &server_hs.sig)?;
                        if server_hs.id_pk.fingerprint() != dest_haven.fingerprint {
                            anyhow::bail!("haven public key verification failed")
                        }
                        shared_sec = Some(my_esk.shared_secret(&server_hs.eph_pk));
                        break;
                    }
                    x => tracing::debug!(
                        "haven sent us something other than a haven handshake: {:?}",
                        x
                    ),
                };
            }
            smol::Timer::after(Duration::from_secs(2u64.pow(i))).await;
        }

        let shared_sec = shared_sec.context("impossible")?;
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

async fn visitor_loop(
    send_downstream: Sender<Bytes>,
    recv_upstream: Receiver<Bytes>,
    rendezvous: RelayFingerprint,
    haven: HavenEndpoint,
    n2r_socket: N2rAnonSocket,
) -> anyhow::Result<()> {
    let rendezvous = RelayEndpoint::new(rendezvous, HAVEN_FORWARD_DOCK);
    // upstream messages are wrapped in V2rMessage
    let up_loop = async {
        loop {
            let to_send = recv_upstream.recv().await?;
            n2r_socket
                .send_to(
                    V2rMessage {
                        dest_haven: haven,
                        payload: HavenMsg::Regular(to_send),
                    }
                    .stdcode()
                    .into(),
                    rendezvous,
                )
                .await?;
        }
    };
    // downstream messages are straight HavenMsgs
    let dn_loop = async {
        loop {
            let (msg, _) = n2r_socket.recv_from().await?;
            let msg: HavenMsg = stdcode::deserialize(&msg)?;
            match msg {
                HavenMsg::Regular(payload) => send_downstream.send(payload).await?,
                _ => tracing::debug!("haven sent a non-regular message"),
            }
        }
    };
    up_loop.race(dn_loop).await
}

/// Represents a running haven, able to accept incoming [HavenPacketConn]s.
pub struct HavenListener {
    _listen_task: Task<anyhow::Result<()>>,
    recv_accepted: Receiver<HavenPacketConn>,
}

impl HavenListener {
    /// Binds a new haven. The rendezvous must be specified.
    pub(super) async fn bind(
        ctx: &V2hNodeCtx,
        identity: HavenIdentitySecret,
        port: u16,
        rendezvous: RelayFingerprint,
    ) -> anyhow::Result<Self> {
        let (send_accepted, recv_accepted) = smol::channel::bounded(100);
        let _listen_task = smolscale::spawn(
            listen_loop(ctx.clone(), identity, port, rendezvous, send_accepted)
                .inspect_err(|e| tracing::error!(err = debug(e), "haven listener loop died")),
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
