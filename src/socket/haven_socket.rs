use std::{convert::Infallible, time::Duration};

use bytes::Bytes;
use clone_macro::clone;
use earendil_crypt::{Fingerprint, IdentitySecret};
use earendil_packet::{crypt::OnionSecret, Dock};
use moka::sync::Cache;
use smol::{
    channel::{Receiver, Sender},
    Task, Timer,
};
use smol_timeout::TimeoutExt;
use smolscale::immortal::{Immortal, RespawnStrategy};
use stdcode::StdcodeSerializeExt;

use crate::{
    daemon::context::DaemonContext,
    global_rpc::{transport::GlobalRpcTransport, GlobalRpcClient},
    haven::{HavenLocator, RegisterHavenReq, HAVEN_FORWARD_DOCK},
};

use super::{
    encrypter::{Encrypter, HavenMsg},
    n2r_socket::N2rSocket,
    Endpoint, SocketRecvError, SocketSendError,
};

pub struct HavenSocket {
    ctx: DaemonContext,
    n2r_socket: N2rSocket,
    identity_sk: IdentitySecret,
    rendezvous_point: Option<Fingerprint>,
    _register_haven_task: Option<Task<()>>,
    /// mapping between destination endpoints and encrypters
    encrypters: Cache<Endpoint, Encrypter>,
    /// buffer for decrypted incoming messages
    recv_incoming: Receiver<(Bytes, Endpoint)>,
    /// task that dispatches not-yet decrypted incoming packets to their right encrypters
    _recv_task: Immortal,
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
        let encrypters: Cache<Endpoint, Encrypter> = Cache::builder()
            .max_capacity(100_000)
            .time_to_live(Duration::from_secs(60 * 30))
            .build();
        let (send_incoming, recv_incoming) = smol::channel::bounded(1000);
        let recv_task = Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!([n2r_socket, encrypters, send_incoming], move || {
                recv_task_loop(
                    n2r_socket.clone(),
                    encrypters.clone(),
                    send_incoming.clone(),
                )
            }),
        );

        if let Some(rob) = rendezvous_point {
            // We're Bob:
            // spawn a task that keeps telling our rendezvous relay node to remember us once in a while
            log::trace!("binding haven with rendezvous_point {}", rob);
            let context = ctx.clone();
            let registration_isk = isk;
            let task = smolscale::spawn(async move {
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
                rendezvous_point,
                _register_haven_task: Some(task),
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
                rendezvous_point,
                _register_haven_task: None,
                encrypters,
                recv_incoming,
                _recv_task: recv_task,
            }
        }
    }

    pub async fn send_to(&self, body: Bytes, endpoint: Endpoint) -> Result<(), SocketSendError> {
        let fwd_body = (body, endpoint).stdcode().into();
        match self.rendezvous_point {
            Some(rob) => {
                // We're Bob:
                let remote_ep = Endpoint::new(rob, HAVEN_FORWARD_DOCK);
                let enc = self.encrypters.get_with(remote_ep, || {
                    Encrypter::new(remote_ep, self.n2r_socket.clone(), None, self.identity_sk)
                });
                enc.send_outgoing(fwd_body).await
            }
            None => {
                // We're Alice:
                // look up Rob's addr in rendezvous dht
                log::trace!(
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
                        log::trace!("found rob in the DHT");
                        let rob = bob_locator.rendezvous_point;
                        let remote_ep = Endpoint::new(rob, HAVEN_FORWARD_DOCK);
                        let enc = self.encrypters.get_with(remote_ep, || {
                            Encrypter::new(
                                remote_ep,
                                self.n2r_socket.clone(),
                                None,
                                self.identity_sk,
                            )
                        });
                        enc.send_outgoing(fwd_body).await
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

async fn recv_task_loop(
    n2r_skt: N2rSocket,
    encrypters: Cache<Endpoint, Encrypter>,
    send_incoming: Sender<(Bytes, Endpoint)>,
) -> anyhow::Result<()> {
    loop {
        let (n2r_msg, _rendezvous_ep) = n2r_skt.recv_from().await?;
        let (body, src_ep): (Bytes, Endpoint) = stdcode::deserialize(&n2r_msg)?;
        let haven_msg: HavenMsg = stdcode::deserialize(&body)?;
        let encrypter = encrypters.get(&src_ep);
        match haven_msg {
            HavenMsg::Handshake(_) => match encrypter {
                Some(enc) => todo!(),
                None => todo!(),
            },
            HavenMsg::Regular { nonce, inner } => match encrypter {
                Some(enc) => todo!(),
                None => anyhow::bail!("stray msg; dropping"),
            },
        }
    }
}

// todo: verify handshake signature

// let mut key_state = encrypter.key_state.lock();

// *key_state = match &*key_state {
//     HavenKeyState::PendingRemote { my_sk } => {
//         let shared_secret = my_sk.shared_secret(&eph_pk);
//         let up_key = blake3::keyed_hash(
//             blake3::hash(b"haven-up").as_bytes(),
//             &shared_secret,
//         );
//         let down_key = blake3::keyed_hash(
//             blake3::hash(b"haven-dn").as_bytes(),
//             &shared_secret,
//         );

//         HavenKeyState::Completed { up_key, down_key }
//     }
//     HavenKeyState::Completed {
//         up_key: _,
//         down_key: _,
//     } => {
//         let new_onion_sk = OnionSecret::generate();
//         let shared_secret = new_onion_sk.shared_secret(&eph_pk);
//         let up_key = blake3::keyed_hash(
//             blake3::hash(b"haven-up").as_bytes(),
//             &shared_secret,
//         );
//         let down_key = blake3::keyed_hash(
//             blake3::hash(b"haven-dn").as_bytes(),
//             &shared_secret,
//         );

//         HavenKeyState::Completed { up_key, down_key }
//     }
//     HavenKeyState::PendingLocal { their_pk } => todo!(),
// };
