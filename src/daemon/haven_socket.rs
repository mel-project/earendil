use std::time::Duration;

use bytes::Bytes;
use earendil_crypt::{Fingerprint, IdentitySecret};
use earendil_packet::{crypt::OnionSecret, Dock};
use smol_timeout::TimeoutExt;
use stdcode::StdcodeSerializeExt;

use super::{
    global_rpc::{transport::GlobalRpcTransport, GlobalRpcClient},
    haven::{RegisterHavenReq, HAVEN_FORWARD_DOCK},
    n2r_socket::{Endpoint, N2rSocket},
    DaemonContext,
};

#[derive(Clone)]
pub struct HavenSocket {
    ctx: DaemonContext,
    n2r_socket: N2rSocket,
    identity_sk: IdentitySecret,
    onion_sk: OnionSecret,
    rendezvous_point: Option<Fingerprint>,
}

impl HavenSocket {
    pub fn bind(
        ctx: DaemonContext,
        identity_sk: IdentitySecret,
        dock: Option<Dock>,
        rendezvous_point: Option<Fingerprint>,
    ) -> HavenSocket {
        let n2r_socket = N2rSocket::bind(ctx.clone(), None, dock);
        if let Some(rob) = rendezvous_point {
            // We're Bob:
            // spawn a task that keeps telling our rendezvous relay node to remember us once in a while
            let context = ctx.clone();
            let isk = identity_sk.clone();
            smolscale::spawn(async move {
                // register forwarding with the rendezvous relay node
                let gclient = GlobalRpcClient(GlobalRpcTransport::new(context.clone(), rob));
                let forward_req = RegisterHavenReq::new(isk);
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
                        _ => log::debug!("registering haven rendezvous relay SUCCEEDED!"),
                    }
                    std::thread::sleep(Duration::from_secs(60 * 50));
                }
            })
            .detach();
        }

        HavenSocket {
            ctx,
            n2r_socket,
            identity_sk,
            onion_sk: OnionSecret::generate(), // TODO: use this for encryption
            rendezvous_point,
        }
    }

    pub async fn send_to(&self, body: Bytes, endpoint: Endpoint) -> anyhow::Result<()> {
        match self.rendezvous_point {
            Some(rob) => {
                // We're Bob:
                // TODO: encrypt body
                // use our N2rSocket to send (endpoint, msg) to Rob
                let fwd_body = (endpoint, body).stdcode();
                self.n2r_socket
                    .send_to(fwd_body.into(), Endpoint::new(rob, HAVEN_FORWARD_DOCK))
                    .await?;
                Ok(())
            }
            None => {
                // We're Alice:
                // look up Rob's addr in rendezvous dht
                match self.ctx.dht_get(endpoint.fingerprint).await? {
                    Some(bob_locator) => {
                        let rob = bob_locator.rendezvous_point;
                        // TODO: encrypt body
                        // use our N2rSocket to send (endpoint, msg) to Rob
                        let fwd_body = (endpoint, body).stdcode();
                        self.n2r_socket
                            .send_to(fwd_body.into(), Endpoint::new(rob, HAVEN_FORWARD_DOCK))
                            .await?;
                        Ok(())
                    }
                    None => anyhow::bail!("could not find rendezvous point for haven"),
                }
            }
        }
    }

    pub async fn recv_from(&self) -> anyhow::Result<(Bytes, Endpoint)> {
        let (n2r_msg, _endpoint) = self.n2r_socket.recv_from().await?;
        // TODO: decrypt
        let inner = stdcode::deserialize(&n2r_msg)?;
        Ok(inner)
    }
}
