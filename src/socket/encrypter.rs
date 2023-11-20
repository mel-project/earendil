use std::sync::Arc;

use bytes::Bytes;
use clone_macro::clone;
use earendil_crypt::{IdentityPublic, IdentitySecret};
use earendil_packet::crypt::{AeadKey, OnionPublic, OnionSecret};
use serde::{Deserialize, Serialize};
use smol::{
    channel::{Receiver, Sender},
    future::FutureExt,
};
use smolscale::immortal::{Immortal, RespawnStrategy};
use stdcode::StdcodeSerializeExt;

use super::{n2r_socket::N2rSocket, Endpoint, SocketRecvError, SocketSendError};

#[derive(Clone)]
pub struct Encrypter {
    send_outgoing: Sender<(Bytes, Endpoint)>,
    send_incoming: Sender<HavenMsg>,
    _task: Arc<Immortal>,
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
        rendezvous_ep: Endpoint,
        n2r_skt: N2rSocket,
        send_incoming: Sender<(Bytes, Endpoint)>,
    ) -> Self {
        let (send_out, recv_out) = smol::channel::bounded(1000);
        let (send_in, recv_in) = smol::channel::bounded(1000);
        let task = Immortal::respawn(RespawnStrategy::Immediate, || async {
            enc_task(
                my_isk,
                n2r_skt,
                remote_ep,
                rendezvous_ep,
                recv_in,
                recv_out,
                send_incoming,
                None,
            )
        });
        Self {
            send_outgoing: send_out,
            send_incoming: send_in,
            _task: Arc::new(task),
        }
    }

    pub fn server_new(
        my_isk: IdentitySecret,
        remote_ep: Endpoint,
        n2r_skt: N2rSocket,
        send_incoming: Sender<(Bytes, Endpoint)>,
        client_hs: Handshake,
    ) -> Self {
        let (send_out, recv_out) = smol::channel::bounded(1000);
        let (send_in, recv_in) = smol::channel::bounded(1000);
        Self {
            send_outgoing: send_out,
            send_incoming: send_in,
            _task: todo!(),
        }
    }

    pub async fn send_outgoing(
        &self,
        msg: Bytes,
        dest_ep: Endpoint,
    ) -> Result<(), SocketSendError> {
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
    rendezvous_ep: Endpoint,
    recv_incoming: Receiver<HavenMsg>,
    recv_outgoing: Receiver<(Bytes, Endpoint)>,
    send_incoming: Sender<(Bytes, Endpoint)>,
    client_hs: Option<Handshake>,
) -> anyhow::Result<()> {
    // complete handshake to get the shared secret
    let my_osk = OnionSecret::generate();
    let my_hs: Bytes = Handshake::new(&my_isk, &my_osk).stdcode().into();
    let shared_sec = match client_hs {
        Some(hs) => {
            hs.id_pk.verify(hs.to_sign().as_bytes(), &hs.sig)?; // verify sig
            n2r_skt
                .send_to((my_hs, remote_ep).stdcode().into(), rendezvous_ep)
                .await?; // respond with server handshake
            my_osk.shared_secret(&hs.eph_pk)
        }
        None => {
            n2r_skt
                .send_to((my_hs, remote_ep).stdcode().into(), remote_ep)
                .await?; // send client handshake
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

    // start up & down loops
    let up_loop = async {
        let mut nonce = 0;
        loop {
            let (msg, remote_ep) = recv_outgoing.recv().await?;
            let ctext = up_key.seal(&pad_nonce(nonce), &msg);
            n2r_skt.send_to(ctext.into(), remote_ep).await?;
            nonce += 1;
        }
    };

    let down_loop = async {
        loop {
            let msg = recv_incoming.recv().await?;
            if let HavenMsg::Regular { nonce, inner } = msg {
                let plain = down_key.open(&pad_nonce(nonce), &inner)?;
                send_incoming.send((plain.into(), remote_ep)).await?
            } else {
                log::debug!("stray message!");
            }
        }
    };

    // race?
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
