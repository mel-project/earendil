use std::{sync::Arc, time::Duration};

use blake3::Hash;
use bytes::Bytes;
use earendil_crypt::{Fingerprint, IdentityPublic, IdentitySecret};
use earendil_packet::{
    crypt::{AeadKey, OnionPublic, OnionSecret},
    Dock,
};
use moka::sync::Cache;
use parking_lot::Mutex;
use replay_filter::ReplayFilter;
use serde::{Deserialize, Serialize};
use smol::{
    channel::{Receiver, Sender},
    Task, Timer,
};
use smol_timeout::TimeoutExt;
use stdcode::StdcodeSerializeExt;

use crate::{
    daemon::context::DaemonContext,
    global_rpc::{transport::GlobalRpcTransport, GlobalRpcClient},
    haven::{HavenLocator, RegisterHavenReq, HAVEN_FORWARD_DOCK},
};

use super::{n2r_socket::N2rSocket, Endpoint, SocketRecvError, SocketSendError};

pub struct HavenSocket {
    ctx: DaemonContext,
    n2r_socket: N2rSocket,
    identity_sk: IdentitySecret,
    onion_sk: OnionSecret,
    rendezvous_point: Option<Fingerprint>,
    _task: Option<Task<()>>,
    /// mapping between destination endpoints and encrypters
    encrypters: Cache<Fingerprint, Encrypter>,
    /// buffer for decrypted incoming messages
    recv_incoming: Receiver<(Bytes, Endpoint)>,
    /// task that dispatches not-yet decrypted incoming packets to their right encrypters
    _recv_task: Task<()>,
}

impl HavenSocket {
    pub fn bind(
        ctx: DaemonContext,
        idsk: IdentitySecret,
        dock: Option<Dock>,
        rendezvous_point: Option<Fingerprint>,
    ) -> HavenSocket {
        let n2r_socket = N2rSocket::bind(ctx.clone(), idsk, dock);
        let isk = idsk;
        let encrypters: Cache<Fingerprint, Encrypter> = Cache::builder()
            .max_capacity(100_000)
            .time_to_live(Duration::from_secs(60 * 30))
            .build();
        let (send_incoming, recv_incoming) = smol::channel::bounded(1000);
        let n2r_socket_clone = n2r_socket.clone();
        let encrypters_clone = encrypters.clone();
        let recv_task = smolscale::spawn(async move {
            loop {
                // todo: _recv_task should recv a msg from the inner n2r skt, call Encrypter::decrypt_incoming() on incoming packets then send them into send_incoming

                if let Ok((n2r_msg, _)) = n2r_socket_clone.recv_from().await {
                    match stdcode::deserialize::<(Bytes, Endpoint)>(&n2r_msg) {
                        Ok((body, source)) => match stdcode::deserialize::<HavenMsg>(&body) {
                            Ok(haven_msg) => {
                                let encrypter = encrypters_clone.get(&source.fingerprint);
                                match encrypter {
                                    Some(encrypter) => match haven_msg {
                                        HavenMsg::Handshake { id_pk, eph_pk, sig } => {
                                            // todo: verify handshake signature

                                            let mut key_state = encrypter.key_state.lock();

                                            *key_state = match &*key_state {
                                                HavenKeyState::Pending { my_sk } => {
                                                    let shared_secret =
                                                        my_sk.shared_secret(&eph_pk);
                                                    let up_key = blake3::keyed_hash(
                                                        blake3::hash(b"haven-up").as_bytes(),
                                                        &shared_secret,
                                                    );
                                                    let down_key = blake3::keyed_hash(
                                                        blake3::hash(b"haven-dn").as_bytes(),
                                                        &shared_secret,
                                                    );

                                                    HavenKeyState::Completed { up_key, down_key }
                                                }
                                                HavenKeyState::Completed {
                                                    up_key: _,
                                                    down_key: _,
                                                } => {
                                                    let new_onion_sk = OnionSecret::generate();
                                                    let shared_secret =
                                                        new_onion_sk.shared_secret(&eph_pk);
                                                    let up_key = blake3::keyed_hash(
                                                        blake3::hash(b"haven-up").as_bytes(),
                                                        &shared_secret,
                                                    );
                                                    let down_key = blake3::keyed_hash(
                                                        blake3::hash(b"haven-dn").as_bytes(),
                                                        &shared_secret,
                                                    );

                                                    HavenKeyState::Completed { up_key, down_key }
                                                }
                                            };
                                        }
                                        HavenMsg::Regular { inner, nonce } => {
                                            let decrypted_msg =
                                                encrypter.decrypt_incoming(inner, nonce);

                                            match decrypted_msg {
                                                Ok(decrypted) => {
                                                    let _ = send_incoming
                                                        .send((decrypted, source))
                                                        .await;
                                                }
                                                Err(e) => log::debug!(
                                                    "failed to decrypt haven message: {e}"
                                                ),
                                            }
                                        }
                                    },
                                    None => {
                                        log::debug!("no encrypter exists for {source}");
                                        match haven_msg {
                                            HavenMsg::Handshake { id_pk, eph_pk, sig } => {
                                                // todo: verify signature

                                                let encrypter = Encrypter::new(
                                                    source,
                                                    &n2r_socket_clone,
                                                    Some(eph_pk),
                                                );
                                                encrypters_clone
                                                    .insert(source.fingerprint, encrypter);
                                            }
                                            HavenMsg::Regular { inner: _, nonce: _ } => {
                                                log::debug!("dropping packet")
                                            }
                                        }
                                    }
                                }
                            }
                            Err(_) => log::debug!("unsupported haven message"),
                        },
                        Err(_) => log::debug!("unable to deserialize N2r body into haven format"),
                    }
                }
            }
        });

        if let Some(rob) = rendezvous_point {
            // We're Bob:
            // spawn a task that keeps telling our rendezvous relay node to remember us once in a while
            log::debug!("binding haven with rendezvous_point {}", rob);
            let context = ctx.clone();
            let registration_isk = isk;
            let task = smolscale::spawn(async move {
                log::debug!("inside haven bind task!!!");
                // generate a new onion keypair
                let onion_sk = OnionSecret::generate();
                let onion_pk = onion_sk.public();
                // register forwarding with the rendezvous relay node
                let gclient = GlobalRpcClient(GlobalRpcTransport::new(context.clone(), idsk, rob));
                let forward_req = RegisterHavenReq::new(registration_isk);
                loop {
                    match gclient
                        .alloc_forward(forward_req.clone())
                        .timeout(Duration::from_secs(30))
                        .await
                    {
                        Some(Err(e)) => {
                            log::debug!("registering haven rendezvous {rob} failed: {:?}", e);
                            Timer::after(Duration::from_secs(3)).await;
                            continue;
                        }
                        None => {
                            log::debug!("registering haven rendezvous relay timed out");
                            Timer::after(Duration::from_secs(3)).await;
                        }
                        _ => {
                            context
                                .dht_insert(HavenLocator::new(registration_isk, onion_pk, rob))
                                .timeout(Duration::from_secs(30))
                                .await;
                            log::debug!("registering haven rendezvous relay SUCCEEDED!");
                            Timer::after(Duration::from_secs(60 * 50)).await;
                        }
                    }
                }
            });

            HavenSocket {
                ctx,
                n2r_socket,
                identity_sk: isk,
                onion_sk: OnionSecret::generate(), // TODO: use this for encryption
                rendezvous_point,
                _task: Some(task),
                encrypters,
                recv_incoming,
                _recv_task: recv_task,
            }
        } else {
            // We're Alice
            HavenSocket {
                ctx,
                n2r_socket,
                identity_sk: isk,
                onion_sk: OnionSecret::generate(), // TODO: use this for encryption
                rendezvous_point,
                _task: None,
                encrypters,
                recv_incoming,
                _recv_task: recv_task,
            }
        }
    }

    pub async fn send_to(&self, body: Bytes, endpoint: Endpoint) -> Result<(), SocketSendError> {
        let fwd_body = (body, endpoint).stdcode();
        match self.rendezvous_point {
            Some(rob) => {
                // We're Bob:
                // TODO: encrypt body
                // use our N2rSocket to send (msg, endpoint) to Rob
                self.n2r_socket
                    .send_to(fwd_body.into(), Endpoint::new(rob, HAVEN_FORWARD_DOCK))
                    .await?;
                Ok(())
            }
            None => {
                // We're Alice:
                // look up Rob's addr in rendezvous dht

                log::debug!(
                    "alice is about to send an earendil packet! looking up {} in the DHT",
                    endpoint.fingerprint
                );
                match self
                    .ctx
                    .dht_get(endpoint.fingerprint)
                    .await
                    .map_err(|_| SocketSendError::DhtError)?
                {
                    Some(bob_locator) => {
                        log::debug!("found rob in the DHT");
                        let rob = bob_locator.rendezvous_point;
                        // TODO: encrypt body
                        // use our N2rSocket to send (msg, endpoint) to Rob
                        self.n2r_socket
                            .send_to(fwd_body.into(), Endpoint::new(rob, HAVEN_FORWARD_DOCK))
                            .await?;
                        Ok(())
                    }
                    None => {
                        log::debug!("couldn't find {} in the DHT", endpoint.fingerprint);
                        Err(SocketSendError::DhtError)
                    }
                }
            }
        }
    }

    pub async fn recv_from(&self) -> Result<(Bytes, Endpoint), SocketRecvError> {
        self.recv_incoming
            .recv_blocking()
            .map_err(|_| SocketRecvError::HavenRecvError)
    }

    pub fn local_endpoint(&self) -> Endpoint {
        self.n2r_socket.local_endpoint()
    }
}

#[derive(Clone)]
struct Encrypter {
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
    nonce: u64,
}

enum HavenKeyState {
    Pending { my_sk: OnionSecret },
    Completed { up_key: Hash, down_key: Hash },
}

impl Encrypter {
    pub fn new(remote_ep: Endpoint, n2r_skt: &N2rSocket, remote_pk: Option<OnionPublic>) -> Self {
        todo!()
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

                let key = AeadKey::from_bytes(down_key.as_bytes());
                let padded_nonce = pad_nonce(nonce);
                let plaintext = Bytes::copy_from_slice(&key.open(&padded_nonce, &ciphertext)?);
                Ok(plaintext)
            }
            HavenKeyState::Pending { my_sk } => {
                anyhow::bail!("handshake pending, dropping packet");
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
enum HavenMsg {
    Handshake {
        id_pk: IdentityPublic,
        eph_pk: OnionPublic,
        sig: [u8; 32],
    },
    Regular {
        nonce: u64,
        inner: Bytes,
    },
}

fn pad_nonce(input: u64) -> [u8; 12] {
    let mut buffer = [0; 12];
    let bytes = input.to_le_bytes();
    buffer[..8].copy_from_slice(&bytes);
    buffer
}
