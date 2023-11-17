use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use earendil_crypt::{Fingerprint, IdentityPublic, IdentitySecret};
use earendil_packet::{
    crypt::{OnionPublic, OnionSecret},
    Dock,
};
use futures_util::TryFutureExt;
use moka::sync::Cache;
use parking_lot::Mutex;
use replay_filter::ReplayFilter;
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
        let encrypters = Cache::builder()
            .max_capacity(100_000)
            .time_to_live(Duration::from_secs(60 * 30))
            .build();
        let (send_incoming, recv_incoming) = smol::channel::bounded(1000);
        let recv_task = smolscale::spawn(async move {
            loop {
                // todo: _recv_task should recv a msg from the inner n2r skt, call Encrypter::decrypt_incoming() on incoming packets then send them into send_incoming

                todo!()
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
    key: Arc<Mutex<HavenKeyState>>,
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
    // Completed { up_key: todo!(), down_key: todo!() }, TODO!
    Pending { my_pk: OnionPublic },
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
    pub fn decrypt_incoming(&self, msg: HavenMsg) -> Bytes {
        todo!()
    }
}

enum HavenMsg {
    Handshake {
        id_pk: IdentityPublic,
        eph_pk: OnionPublic,
        sig: [u8; 32],
    },
    Regular {
        inner: Bytes,
    },
}
