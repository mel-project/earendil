use std::convert::Infallible;
use std::time::Duration;

use anyhow::Context;
use bytes::Bytes;
use earendil_crypt::{
    HavenFingerprint, HavenIdentityPublic, HavenIdentitySecret, RelayFingerprint,
};
use earendil_packet::crypt::{AeadKey, OnionPublic, OnionSecret};
use futures_util::{future::Shared, FutureExt};
use replay_filter::ReplayFilter;
use serde::{Deserialize, Serialize};
use smol::future::FutureExt as Fe;
use smol::{
    channel::{Receiver, Sender},
    Task,
};
use smol_timeout::TimeoutExt;
use stdcode::StdcodeSerializeExt;

use crate::{context::DaemonContext, haven_util::HAVEN_FORWARD_DOCK};
use crate::{control_protocol::DhtError, daemon::dht::dht_get};

use super::n2r_socket::N2rClientSocket;
use super::HavenEndpoint;
use super::RelayEndpoint;

#[derive(Clone)]
pub struct CryptSession {
    send_outgoing: Sender<Bytes>,
    send_incoming: Sender<HavenMsg>,
    _task: Shared<Task<String>>, // returns an error string
}

#[derive(Clone, Serialize, Deserialize)]
pub enum HavenMsg {
    ClientHs(Handshake),
    ServerHs(Handshake),
    Regular { nonce: u64, inner: Bytes },
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Handshake {
    id_pk: HavenIdentityPublic,
    eph_pk: OnionPublic,
    sig: Bytes,
}

impl CryptSession {
    pub fn new(
        my_isk: HavenIdentitySecret,
        remote: HavenEndpoint,
        rendezvous_fp: Option<RelayFingerprint>,
        n2r_skt: N2rClientSocket,
        send_incoming_decrypted: Sender<(Bytes, HavenEndpoint)>,
        ctx: DaemonContext,
        client_info: Option<(Handshake, HavenFingerprint)>,
    ) -> anyhow::Result<Self> {
        if let Some((hs, fp)) = client_info.clone() {
            hs.id_pk.verify(hs.to_sign().as_bytes(), &hs.sig)?; // verify sig & src_fp
            if hs.id_pk.fingerprint() != fp {
                anyhow::bail!("spoofed src fingerprint for ClientHandshake!")
            }
        }
        let (send_out, recv_out) = smol::channel::unbounded();
        let (send_in, recv_in) = smol::channel::unbounded();
        let task = smolscale::spawn(
            enc_task(
                my_isk,
                n2r_skt,
                remote,
                rendezvous_fp,
                recv_in,
                recv_out,
                send_incoming_decrypted,
                client_info.map(|(hs, _)| hs),
                ctx,
            )
            .map(move |e| format!("{:?}", e.unwrap_err())),
        );
        Ok(Self {
            send_outgoing: send_out,
            send_incoming: send_in,
            _task: task.shared(),
        })
    }

    async fn wait_error(&self) -> anyhow::Result<()> {
        Err(anyhow::anyhow!(self._task.clone().await))
    }

    pub async fn send_outgoing(&self, msg: Bytes) -> anyhow::Result<()> {
        if self.send_outgoing.send(msg).await.is_err() {
            // channel is unbounded
            self.wait_error().await
        } else {
            Ok(())
        }
    }

    pub async fn send_incoming(&self, msg: HavenMsg) -> anyhow::Result<()> {
        if self.send_incoming.send(msg).await.is_err() {
            // channel is unbounded
            self.wait_error().await
        } else {
            Ok(())
        }
    }
}

#[tracing::instrument(skip(n2r_skt, recv_incoming, recv_outgoing, client_hs, ctx))]
async fn enc_task(
    my_isk: HavenIdentitySecret,
    n2r_skt: N2rClientSocket,
    remote: HavenEndpoint,
    rendezvous_fp: Option<RelayFingerprint>,
    recv_incoming: Receiver<HavenMsg>,
    recv_outgoing: Receiver<Bytes>,
    send_incoming_decrypted: Sender<(Bytes, HavenEndpoint)>,
    client_hs: Option<Handshake>,
    ctx: DaemonContext,
) -> anyhow::Result<Infallible> {
    let send_to_rendezvous = |msg: Bytes| async {
        let fwd_body = (msg, remote).stdcode();
        let rendezvous_ep = match rendezvous_fp {
            Some(rendezvous) => {
                // We're the server
                RelayEndpoint::new(rendezvous, HAVEN_FORWARD_DOCK)
            }
            None => {
                // We're the client: look up Rob's addr in rendezvous dht
                let rendezvous_locator = dht_get(&ctx, remote.fingerprint, n2r_skt.clone())
                    .timeout(Duration::from_secs(30))
                    .await
                    .map_or(
                        Err(DhtError::NetworkFailure(
                            "dht_get({key}) timed out".to_owned(),
                        )),
                        |res| res,
                    )
                    .context(format!("DHT failed for {}", remote.fingerprint))?
                    .context(format!("DHT returned None for {}", remote.fingerprint))?;
                RelayEndpoint::new(rendezvous_locator.rendezvous_point, HAVEN_FORWARD_DOCK)
            }
        };
        n2r_skt.send_to(fwd_body.into(), rendezvous_ep).await?;
        anyhow::Ok(())
    };

    // complete handshake to get the shared secret
    let my_osk = OnionSecret::generate();
    let my_hs = Handshake::new(&my_isk, &my_osk);
    let shared_sec = match client_hs {
        Some(hs) => {
            // we already verified the signature in the Encrypter constructor
            let msg = HavenMsg::ServerHs(my_hs).stdcode().into();
            send_to_rendezvous(msg).await?; // respond with server handshake
            my_osk.shared_secret(&hs.eph_pk)
        }
        None => {
            let msg = HavenMsg::ClientHs(my_hs).stdcode().into();
            send_to_rendezvous(msg).await?; // send client handshake
            loop {
                let in_msg = recv_incoming.recv().await?;
                if let HavenMsg::ServerHs(hs) = in_msg {
                    break my_osk.shared_secret(&hs.eph_pk);
                }
            }
        }
    };
    let up_key = AeadKey::from_bytes(
        blake3::keyed_hash(blake3::hash(b"haven-up").as_bytes(), &shared_sec).as_bytes(),
    );
    let down_key = AeadKey::from_bytes(
        blake3::keyed_hash(blake3::hash(b"haven-dn").as_bytes(), &shared_sec).as_bytes(),
    );
    let (enc_key, dec_key) = if rendezvous_fp.is_none() {
        (up_key, down_key) // we're the client
    } else {
        (down_key, up_key) // we're the server
    };

    // start up & down loops
    let up_loop = async {
        let mut nonce = 0;
        loop {
            let msg = recv_outgoing.recv().await?;
            let ctext = enc_key.seal(&pad_nonce(nonce), &msg);
            let msg = HavenMsg::Regular {
                nonce,
                inner: ctext.into(),
            }
            .stdcode();
            send_to_rendezvous(msg.into()).await?;
            nonce += 1;
        }
    };

    let down_loop = async {
        let mut rf = ReplayFilter::default();
        loop {
            let msg = recv_incoming.recv().await?;
            if let HavenMsg::Regular { nonce, inner } = msg {
                if rf.add(nonce) {
                    let plain = dec_key.open(&pad_nonce(nonce), &inner)?;
                    let _ = send_incoming_decrypted.try_send((plain.into(), remote));
                } else {
                    tracing::debug!("received pkt with duplicate nonce! dropping...")
                }
            } else {
                tracing::debug!("stray handshake message!");
            }
        }
    };
    up_loop.race(down_loop).await
}

impl Handshake {
    /// Creates a Handshake from an IdentitySecret
    pub fn new(id_sk: &HavenIdentitySecret, onion_sk: &OnionSecret) -> Self {
        let id_pk = id_sk.public();
        let eph_pk = onion_sk.public();
        let mut hdsk = Handshake {
            id_pk,
            eph_pk,
            sig: Bytes::new(),
        };
        hdsk.sig = id_sk.sign(hdsk.to_sign().as_bytes());
        hdsk
    }

    /// The value that the signatures are supposed to be computed against.
    pub fn to_sign(&self) -> blake3::Hash {
        let mut this = self.clone();
        this.sig = Bytes::new();
        blake3::keyed_hash(b"haven_handshake_________________", &this.stdcode())
    }
}

fn pad_nonce(input: u64) -> [u8; 12] {
    let mut buffer = [0; 12];
    let bytes = input.to_le_bytes();
    buffer[..8].copy_from_slice(&bytes);
    buffer
}
