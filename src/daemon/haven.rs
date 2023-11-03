use bytes::Bytes;
use earendil_crypt::{Fingerprint, IdentityPublic, IdentitySecret};
use earendil_packet::crypt::OnionPublic;
use serde::{Deserialize, Serialize};
use stdcode::StdcodeSerializeExt;

use super::n2r_socket::N2rSocket;

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
    n2r_socket: N2rSocket,
}

impl HavenSocket {
    pub fn bind(&self) {
        todo!()
    }
    pub fn send(&self) {
        todo!()
    }
    pub fn recv(&self) {
        todo!()
    }
}
