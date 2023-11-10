use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use earendil_crypt::{Fingerprint, IdentitySecret};
use earendil_packet::{crypt::OnionSecret, Dock};
use smol::{Task, Timer};
use smol_timeout::TimeoutExt;
use stdcode::StdcodeSerializeExt;

use crate::daemon::haven::HavenLocator;

use super::{
    global_rpc::{transport::GlobalRpcTransport, GlobalRpcClient},
    haven::{RegisterHavenReq, HAVEN_FORWARD_DOCK},
    n2r_socket::{Endpoint, N2rSocket},
    socket::{SocketRecvError, SocketSendError},
    DaemonContext,
};

pub struct HavenSocket {
    ctx: DaemonContext,
    n2r_socket: N2rSocket,
    identity_sk: IdentitySecret,
    onion_sk: OnionSecret,
    rendezvous_point: Option<Fingerprint>,
    _task: Option<Task<()>>,
}

impl HavenSocket {
    pub fn bind(
        ctx: DaemonContext,
        identity_sk: Option<IdentitySecret>,
        dock: Option<Dock>,
        rendezvous_point: Option<Fingerprint>,
    ) -> HavenSocket {
        let n2r_socket = N2rSocket::bind(ctx.clone(), identity_sk.clone(), dock);
        let isk = match identity_sk {
            Some(isk) => isk,
            None => Arc::clone(&ctx.identity).as_ref().clone(),
        };

        log::debug!("binding haven with rendezvous_point {:?}", rendezvous_point);
        if let Some(rob) = rendezvous_point {
            // We're Bob:
            // spawn a task that keeps telling our rendezvous relay node to remember us once in a while
            let context = ctx.clone();
            let registration_isk = isk.clone();
            let task = smolscale::spawn(async move {
                log::debug!("inside haven bind task!!!");
                // generate a new onion keypair
                let onion_sk = OnionSecret::generate();
                let onion_pk = onion_sk.public();
                // register forwarding with the rendezvous relay node
                let gclient = GlobalRpcClient(GlobalRpcTransport::new(context.clone(), rob));
                let forward_req = RegisterHavenReq::new(registration_isk.clone());
                loop {
                    match gclient
                        .alloc_forward(forward_req.clone())
                        .timeout(Duration::from_secs(30))
                        .await
                    {
                        Some(Err(e)) => {
                            log::debug!("registering haven rendezvous {rob} failed: {:?}", e)
                        }
                        None => log::debug!("registering haven rendezvous relay timed out"),
                        _ => {
                            match gclient
                                .dht_insert(
                                    HavenLocator::new(registration_isk.clone(), onion_pk, rob),
                                    true,
                                )
                                .timeout(Duration::from_secs(30))
                                .await
                            {
                                Some(Err(e)) => {
                                    log::debug!("inserting HavenLocator into dht failed: {:?}", e)
                                }
                                None => log::debug!("inserting HavenLocator into dht timed out"),
                                _ => log::debug!("registering haven rendezvous relay SUCCEEDED!"),
                            };
                        }
                    }
                    Timer::after(Duration::from_secs(60 * 50)).await;
                }
            });

            HavenSocket {
                ctx,
                n2r_socket,
                identity_sk: isk,
                onion_sk: OnionSecret::generate(), // TODO: use this for encryption
                rendezvous_point,
                _task: Some(task),
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
        let (n2r_msg, _) = self.n2r_socket.recv_from().await?;
        // TODO: decrypt
        let inner =
            stdcode::deserialize(&n2r_msg).map_err(|_| SocketRecvError::HavenMsgBadFormat)?;
        Ok(inner)
    }
}
