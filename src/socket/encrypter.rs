use std::sync::Arc;

use anyhow::Context;
use bytes::Bytes;
use earendil_crypt::{Fingerprint, IdentityPublic, IdentitySecret};
use earendil_packet::crypt::{AeadKey, OnionPublic, OnionSecret};
use serde::{Deserialize, Serialize};
use smol::{
    channel::{Receiver, Sender},
    future::FutureExt,
    Task,
};
use stdcode::StdcodeSerializeExt;

use crate::{daemon::context::DaemonContext, haven::HAVEN_FORWARD_DOCK};

use super::{n2r_socket::N2rSocket, Endpoint, SocketRecvError, SocketSendError};

#[derive(Clone)]
pub struct Encrypter {
    send_outgoing: Sender<Bytes>,
    send_incoming: Sender<HavenMsg>,
    _task: Arc<Task<anyhow::Result<()>>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum HavenMsg {
    ClientHs(Handshake),
    ServerHs(Handshake),
    Regular { nonce: u64, inner: Bytes },
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Handshake {
    id_pk: IdentityPublic,
    eph_pk: OnionPublic,
    sig: Bytes,
}

impl Encrypter {
    pub fn client_new(
        my_isk: IdentitySecret,
        remote_ep: Endpoint,
        rendezvous_fp: Option<Fingerprint>,
        n2r_skt: N2rSocket,
        send_incoming_decrypted: Sender<(Bytes, Endpoint)>,
        ctx: DaemonContext,
    ) -> Self {
        let (send_out, recv_out) = smol::channel::bounded(1000);
        let (send_in, recv_in) = smol::channel::bounded(1000);
        let task = smolscale::spawn(enc_task(
            my_isk,
            n2r_skt,
            remote_ep,
            rendezvous_fp,
            recv_in,
            recv_out,
            send_incoming_decrypted,
            None,
            ctx,
        ));
        Self {
            send_outgoing: send_out,
            send_incoming: send_in,
            _task: Arc::new(task),
        }
    }

    pub fn server_new(
        my_isk: IdentitySecret,
        remote_ep: Endpoint,
        rendezvous_fp: Option<Fingerprint>,
        n2r_skt: N2rSocket,
        send_incoming_decrypted: Sender<(Bytes, Endpoint)>,
        client_hs: Handshake,
        ctx: DaemonContext,
    ) -> Self {
        let (send_out, recv_out) = smol::channel::bounded(1000);
        let (send_in, recv_in) = smol::channel::bounded(1000);
        let task = smolscale::spawn(enc_task(
            my_isk,
            n2r_skt,
            remote_ep,
            rendezvous_fp,
            recv_in,
            recv_out,
            send_incoming_decrypted,
            Some(client_hs),
            ctx,
        ));
        Self {
            send_outgoing: send_out,
            send_incoming: send_in,
            _task: Arc::new(task),
        }
    }

    pub async fn send_outgoing(&self, msg: Bytes) -> Result<(), SocketSendError> {
        self.send_outgoing
            .send(msg)
            .await
            .map_err(|_| SocketSendError::HavenSendError)
    }

    pub async fn send_incoming(&self, msg: HavenMsg) -> Result<(), SocketRecvError> {
        self.send_incoming
            .send(msg)
            .await
            .map_err(|_| SocketRecvError::HavenRecvError)
    }
}

async fn enc_task(
    my_isk: IdentitySecret,
    n2r_skt: N2rSocket,
    remote_ep: Endpoint,
    rendezvous_fp: Option<Fingerprint>,
    recv_incoming: Receiver<HavenMsg>,
    recv_outgoing: Receiver<Bytes>,
    send_incoming_decrypted: Sender<(Bytes, Endpoint)>,
    client_hs: Option<Handshake>,
    ctx: DaemonContext,
) -> anyhow::Result<()> {
    // get rendezvous ep
    let rendezvous_ep = match rendezvous_fp {
        Some(rob) => {
            // We're the server
            Endpoint::new(rob, HAVEN_FORWARD_DOCK)
        }
        None => {
            // We're the client: look up Rob's addr in rendezvous dht
            log::trace!(
                "alice is about to send an earendil packet! looking up {} in the DHT",
                remote_ep.fingerprint
            );
            let bob_locator = ctx
                .dht_get(remote_ep.fingerprint)
                .await
                .map_err(|_| SocketSendError::DhtError)?
                .context("Could not get rendezvous for {endpoint}")
                .map_err(|_| SocketSendError::HavenSendError)?;
            log::trace!("found rob in the DHT");
            Endpoint::new(bob_locator.rendezvous_point, HAVEN_FORWARD_DOCK)
        }
    };
    log::debug!("rendezvous_ep = {rendezvous_ep}");
    // complete handshake to get the shared secret
    let my_osk = OnionSecret::generate();
    let my_hs = Handshake::new(&my_isk, &my_osk);
    let shared_sec = match client_hs {
        Some(hs) => {
            log::debug!("lol computing shared_secret!!@!");
            hs.id_pk.verify(hs.to_sign().as_bytes(), &hs.sig)?; // verify sig
            log::debug!("sending server handshake!");
            let msg = (HavenMsg::ServerHs(my_hs).stdcode(), remote_ep)
                .stdcode()
                .into();
            n2r_skt.send_to(msg, rendezvous_ep).await?; // respond with server handshake
            my_osk.shared_secret(&hs.eph_pk)
        }
        None => {
            log::debug!("lol computing shared_secret!!@!");
            log::debug!("sending client handshake!");
            let msg = (HavenMsg::ClientHs(my_hs).stdcode(), remote_ep)
                .stdcode()
                .into();
            n2r_skt.send_to(msg, rendezvous_ep).await?; // send client handshake
            loop {
                let in_msg = recv_incoming.recv().await?;
                if let HavenMsg::ServerHs(hs) = in_msg {
                    break my_osk.shared_secret(&hs.eph_pk);
                }
            }
        }
    };
    log::trace!("Encrypter got shared_sec {}!", blake3::hash(&shared_sec));
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
            n2r_skt
                .send_to((msg, remote_ep).stdcode().into(), rendezvous_ep)
                .await?;
            nonce += 1;
        }
    };

    let down_loop = async {
        loop {
            let msg = recv_incoming.recv().await?;
            log::debug!("Encrypter down_loop: got msg!!!!");
            if let HavenMsg::Regular { nonce, inner } = msg {
                log::debug!("it's a regular haven msg!");
                let plain = dec_key.open(&pad_nonce(nonce), &inner)?;
                log::debug!("opened!");
                send_incoming_decrypted
                    .send((plain.into(), remote_ep))
                    .await?
            } else {
                log::info!("stray handshake message!");
            }
        }
    };
    up_loop.race(down_loop).await
}

impl Handshake {
    /// Creates a Handshake from an IdentitySecret
    pub fn new(id_sk: &IdentitySecret, onion_sk: &OnionSecret) -> Self {
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
