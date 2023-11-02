use bytes::Bytes;
use earendil_crypt::{Fingerprint, IdentityPublic};
use earendil_packet::crypt::OnionPublic;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HavenLocator {
    identity_pk: IdentityPublic,
    onion_pk: OnionPublic,
    rendezvous_fingerprint: Fingerprint,
    signature: Bytes,
}

impl HavenLocator {
    pub fn new(
        identity_pk: IdentityPublic,
        onion_pk: OnionPublic,
        rendezvous_fingerprint: Fingerprint,
        signature: Bytes,
    ) -> HavenLocator {
        HavenLocator {
            identity_pk,
            onion_pk,
            rendezvous_fingerprint,
            signature,
        }
    }

    pub fn get_id_pk(&self) -> IdentityPublic {
        self.identity_pk
    }

    pub fn get_onion_pk(&self) -> OnionPublic {
        self.onion_pk
    }

    pub fn get_rendezvous_fp(&self) -> Fingerprint {
        self.rendezvous_fingerprint
    }

    pub fn get_signature(&self) -> Bytes {
        self.signature.clone()
    }

    pub fn signable(&self) -> HavenLocator {
        HavenLocator::new(
            self.identity_pk,
            self.onion_pk,
            self.rendezvous_fingerprint,
            Bytes::new(),
        )
    }
}
