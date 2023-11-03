use std::time::Duration;

use bytes::Bytes;
use earendil_crypt::{Fingerprint, IdentityPublic, IdentitySecret};
use earendil_packet::{crypt::OnionPublic, Dock};
use rand::RngCore;
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

#[derive(Clone)]
pub struct HavenSocket {
    ctx: DaemonContext,
    n2r_socket: N2rSocket,
}

impl HavenSocket {
    pub async fn bind(
        ctx: DaemonContext,
        dock: Option<Dock>,
        host_descriptor: Option<HavenHostDescriptor>,
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

            HavenHostDescriptor {
                identity_sk: IdentitySecret::generate(),
                rendezvous_fingerprint: rendezvous_relay_fp,
            }
        };

        // spawn a task that keeps telling our rendezvous relay node to remember us every few
        // minutes
        smolscale::spawn(async move {
            let ctx = ctx.clone();
            loop {
                let descriptor = descriptor.clone();
                // register forwarding with the rendezvous relay node
                let gclient = GlobalRpcClient(GlobalRpcTransport::new(
                    ctx.clone(),
                    descriptor.rendezvous_fingerprint,
                ));
                let forward_req = ForwardRequest::new(descriptor.identity_sk);
                match gclient
                    .alloc_forward(forward_req)
                    .timeout(Duration::from_secs(10))
                    .await
                {
                    Some(Err(e)) => log::debug!(
                        "registering haven rendezvous {} failed: {:?}",
                        descriptor.rendezvous_fingerprint.to_string(),
                        e
                    ),
                    None => log::debug!("registering haven rendezvous relay timed out"),
                    _ => {}
                }

                std::thread::sleep(Duration::from_secs(60 * 60));
            }
        })
        .detach();

        HavenSocket { ctx, n2r_socket }
    }

    pub fn send(&self, fingerprint: Fingerprint, dock: Dock) {
        todo!()
    }

    pub fn recv(&self) {
        todo!()
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct HavenHostDescriptor {
    identity_sk: IdentitySecret,
    rendezvous_fingerprint: Fingerprint,
}
