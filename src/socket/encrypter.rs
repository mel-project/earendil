use bytes::Bytes;
use earendil_crypt::{IdentityPublic, IdentitySecret};
use earendil_packet::crypt::{AeadKey, OnionPublic, OnionSecret};
use parking_lot::Mutex;
use replay_filter::ReplayFilter;
use serde::{Deserialize, Serialize};
use smol::{
    channel::{Receiver, Sender},
    Task, Timer,
};
use std::{sync::Arc, time::Duration};
use stdcode::StdcodeSerializeExt;

use super::{n2r_socket::N2rSocket, Endpoint, SocketSendError};

#[derive(Clone)]
pub struct Encrypter {
    remote_ep: Endpoint,
    /// haven encryption keys
    key_state: Arc<Mutex<HavenKeyState>>,
    /// up packet buffer
    send_outgoing: Sender<Bytes>,
    recv_outgoing: Receiver<Bytes>,
    /// task containing two loops; the first one completes the handshake, and the second one sends outgoing packets from the buffer onto the network
    _up_task: Arc<Task<()>>,
    /// inner N2rSocket of the haven socket
    n2r_skt: N2rSocket, // ?? (not sure about this type)
    replay_filter: Arc<ReplayFilter>,
    nonce: Arc<Mutex<u64>>,
}

#[derive(Clone)]
pub enum HavenKeyState {
    PendingStart,
    PendingRemote { my_sk: OnionSecret },
    PendingLocal { their_pk: OnionPublic },
    Completed { up_key: AeadKey, down_key: AeadKey },
}

impl Encrypter {
    pub fn new(
        remote_ep: Endpoint,
        n2r_skt: N2rSocket,
        remote_pk: Option<OnionPublic>,
        idsk: IdentitySecret,
    ) -> Self {
        let key_state = Arc::new(Mutex::new(HavenKeyState::PendingStart));
        let nonce = Arc::new(Mutex::new(0));
        let (send_outgoing, recv_outgoing) = smol::channel::bounded(1000);
        match remote_pk {
            Some(rpk) => Self {
                remote_ep,
                key_state,
                send_outgoing,
                recv_outgoing,
                _up_task: todo!(),
                n2r_skt,
                replay_filter: Arc::new(ReplayFilter::default()),
                nonce,
            },
            None => Self {
                remote_ep,
                key_state: key_state.clone(),
                send_outgoing,
                recv_outgoing: recv_outgoing.clone(),
                _up_task: Arc::new(smolscale::spawn(up_task(
                    idsk,
                    remote_ep,
                    key_state,
                    n2r_skt.clone(),
                    recv_outgoing,
                    nonce.clone(),
                ))),
                n2r_skt,
                replay_filter: Arc::new(ReplayFilter::default()),
                nonce,
            },
        }
    }
    /// sends an outgoing mesage into the Encryptor, which takes care of haven-encrypting it and getting it to the network
    pub async fn send_outgoing(&self, msg: Bytes) -> Result<(), SocketSendError> {
        self.send_outgoing
            .send(msg)
            .await
            .map_err(|_| SocketSendError::HavenSendError)
    }

    /// send an incoming msg into the Encryptor
    pub fn decrypt_incoming(&self, ciphertext: Bytes, nonce: u64) -> anyhow::Result<Bytes> {
        match &*self.key_state.lock() {
            HavenKeyState::Completed { up_key, down_key } => {
                // todo: check filter for replays

                let padded_nonce = pad_nonce(nonce);
                let plaintext = Bytes::copy_from_slice(&down_key.open(&padded_nonce, &ciphertext)?);
                Ok(plaintext)
            }
            _ => {
                anyhow::bail!("handshake pending, dropping packet");
            }
        }
    }
}

async fn up_task(
    my_id: IdentitySecret,
    remote_ep: Endpoint,
    key_state: Arc<Mutex<HavenKeyState>>,
    n2r_skt: N2rSocket,
    recv_outgoing: Receiver<Bytes>,
    nonce: Arc<Mutex<u64>>,
) {
    // 1st loop: completes handshake
    loop {
        let state = (*key_state.lock()).clone();
        match state {
            HavenKeyState::PendingStart => {
                let my_osk = OnionSecret::generate();
                let handshake = Handshake::new(&my_id, &my_osk);
                match n2r_skt
                    .send_to(
                        HavenMsg::Handshake(handshake.clone()).stdcode().into(),
                        remote_ep,
                    )
                    .await
                {
                    Ok(_) => *key_state.lock() = HavenKeyState::PendingRemote { my_sk: my_osk },
                    Err(e) => {
                        log::warn!("sending handshake FAILED with ERR {e}, RETRYING...");
                        Timer::after(Duration::from_secs(1)).await;
                    }
                }
            }
            HavenKeyState::PendingRemote { my_sk: _ } => {
                // our HavenSocket's recv_task will handle this
                Timer::after(Duration::from_secs(1));
            }
            HavenKeyState::PendingLocal { their_pk } => {
                let my_osk = OnionSecret::generate();
                let (up_key, down_key) = calculate_keys(&my_osk, &their_pk);
                // send handshake
                let handshake = Handshake::new(&my_id, &my_osk);

                match n2r_skt
                    .send_to(
                        HavenMsg::Handshake(handshake.clone()).stdcode().into(),
                        remote_ep,
                    )
                    .await
                {
                    Ok(_) => {
                        *key_state.lock() = HavenKeyState::Completed { up_key, down_key };
                        break;
                    }
                    Err(e) => {
                        log::warn!("sending handshake FAILED with ERR {e}, RETRYING...");
                        Timer::after(Duration::from_secs(1)).await;
                    }
                }
            }
            HavenKeyState::Completed {
                up_key: _,
                down_key: _,
            } => {
                log::debug!("haven encryption handshake COMPLETED! *v*");
                break;
            }
        }
    }
    // 2nd loop: encrypts & sends msg to remote
    loop {
        match recv_outgoing.recv().await {
            Ok(plain) => {
                let key_state = (*key_state.lock()).clone();
                match key_state {
                    HavenKeyState::Completed {
                        up_key,
                        down_key: _,
                    } => {
                        // encrypt with nonce
                        let nonce = *nonce.lock();
                        let msg = up_key.seal(&pad_nonce(nonce), &plain);
                        // send off!
                        let _ = n2r_skt.send_to(msg.into(), remote_ep).await;
                    }
                    _ => {
                        log::debug!("waiting for encryption handshake to complete; dropping packet")
                    }
                }
            }
            Err(e) => log::debug!("ERROR receiving outgoing msg in ENCRYPTER! {e}"),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum HavenMsg {
    Handshake(Handshake),
    Regular { nonce: u64, inner: Bytes },
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Handshake {
    id_pk: IdentityPublic,
    eph_pk: OnionPublic,
    sig: Bytes,
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

fn calculate_keys(osk: &OnionSecret, opk: &OnionPublic) -> (AeadKey, AeadKey) {
    let shared_secret = osk.shared_secret(&opk);
    let up_key = blake3::keyed_hash(blake3::hash(b"haven-up").as_bytes(), &shared_secret);
    let down_key = blake3::keyed_hash(blake3::hash(b"haven-dn").as_bytes(), &shared_secret);
    (
        AeadKey::from_bytes(up_key.as_bytes()),
        AeadKey::from_bytes(down_key.as_bytes()),
    )
}

fn pad_nonce(input: u64) -> [u8; 12] {
    let mut buffer = [0; 12];
    let bytes = input.to_le_bytes();
    buffer[..8].copy_from_slice(&bytes);
    buffer
}
