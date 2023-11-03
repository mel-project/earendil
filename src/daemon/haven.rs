use std::time::Duration;

use bytes::Bytes;
use earendil_crypt::{Fingerprint, IdentityPublic, IdentitySecret};
use earendil_packet::{
    crypt::{box_decrypt, OnionPublic, OnionSecret},
    Dock,
};
use serde::{Deserialize, Serialize};
use smol_timeout::TimeoutExt;
use stdcode::StdcodeSerializeExt;

use crate::daemon::{
    global_rpc::{transport::GlobalRpcTransport, GlobalRpcClient},
    rendezvous::ForwardRequest,
};

use super::{n2r_socket::N2rSocket, DaemonContext};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HavenLocator {
    pub identity_pk: IdentityPublic,
    pub onion_pk: OnionPublic,
    pub rendezvous_fingerprint: Fingerprint,
    pub signature: Bytes,
}

impl HavenLocator {
    pub fn new(
        identity_sk: IdentitySecret,
        onion_pk: OnionPublic,
        rendezvous_fingerprint: Fingerprint,
    ) -> HavenLocator {
        let identity_pk = identity_sk.public();
        let locator = HavenLocator {
            identity_pk,
            onion_pk,
            rendezvous_fingerprint,
            signature: Bytes::new(),
        };
        let signature = identity_sk.sign(&locator.signable());

        HavenLocator {
            identity_pk,
            onion_pk,
            rendezvous_fingerprint,
            signature,
        }
    }

    pub fn signable(&self) -> [u8; 32] {
        let locator = HavenLocator {
            identity_pk: self.identity_pk,
            onion_pk: self.onion_pk,
            rendezvous_fingerprint: self.rendezvous_fingerprint,
            signature: Bytes::new(),
        };
        let hash = blake3::keyed_hash(b"haven_locator___________________", &locator.stdcode());

        *hash.as_bytes()
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct HavenMessage {
    sender: Fingerprint,
    inner: Bytes,
}

#[derive(Clone)]
pub struct HavenSocket {
    ctx: DaemonContext,
    n2r_socket: N2rSocket,
    host_descriptor: HostDescriptor,
}

impl HavenSocket {
    pub fn bind(
        ctx: DaemonContext,
        dock: Option<Dock>,
        host_descriptor: Option<HostDescriptor>,
    ) -> HavenSocket {
        let n2r_socket = N2rSocket::bind(ctx.clone(), None, dock);

        let descriptor = if let Some(descriptor) = host_descriptor {
            descriptor
        } else {
            // pick a random relay as our rendezvous node if not specified
            let rendezvous_relay_fp = ctx
                .relay_graph
                .read()
                .random_adjacency()
                .expect("empty relay graph")
                .left;

            HostDescriptor {
                identity_sk: IdentitySecret::generate(),
                onion_sk: OnionSecret::generate(),
                rendezvous_fingerprint: rendezvous_relay_fp,
            }
        };

        // spawn a task that keeps telling our rendezvous relay node to remember us once in a while
        let context = ctx.clone();
        let desc = descriptor.clone();
        smolscale::spawn(async move {
            // register forwarding with the rendezvous relay node
            let gclient = GlobalRpcClient(GlobalRpcTransport::new(
                context.clone(),
                desc.rendezvous_fingerprint,
            ));
            let forward_req = ForwardRequest::new(desc.clone().identity_sk);
            loop {
                match gclient
                    .alloc_forward(forward_req.clone())
                    .timeout(Duration::from_secs(10))
                    .await
                {
                    Some(Err(e)) => log::debug!(
                        "registering haven rendezvous {} failed: {:?}",
                        desc.rendezvous_fingerprint.to_string(),
                        e
                    ),
                    None => log::debug!("registering haven rendezvous relay timed out"),
                    _ => {}
                }

                std::thread::sleep(Duration::from_secs(60 * 50));
            }
        })
        .detach();

        HavenSocket {
            ctx,
            n2r_socket,
            host_descriptor: descriptor,
        }
    }

    pub fn send(&self, fingerprint: Fingerprint, dock: Dock) {
        todo!()
    }

    pub async fn recv(&self) -> anyhow::Result<HavenMessage> {
        let (n2r_msg, _endpoint) = self.n2r_socket.recv_from().await?;
        let (decrypted_msg, _) = box_decrypt(&n2r_msg, &self.host_descriptor.onion_sk)?;
        let haven_msg: HavenMessage = stdcode::deserialize(&decrypted_msg)?;

        Ok(haven_msg)
    }
}

#[derive(Clone)]
pub struct HostDescriptor {
    identity_sk: IdentitySecret,
    onion_sk: OnionSecret,
    rendezvous_fingerprint: Fingerprint,
}
