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
    fn new(
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

    fn signable(&self) -> HavenLocator {
        HavenLocator::new(
            self.identity_pk,
            self.onion_pk,
            self.rendezvous_fingerprint,
            Bytes::new(),
        )
    }
}
