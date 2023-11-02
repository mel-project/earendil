use bytes::Bytes;
use earendil_crypt::{Fingerprint, IdentityPublic, IdentitySecret};
use earendil_packet::crypt::OnionPublic;
use serde::{Deserialize, Serialize};
use stdcode::StdcodeSerializeExt;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HavenLocator {
    identity_pk: IdentityPublic,
    onion_pk: OnionPublic,
    rendezvous_fingerprint: Fingerprint,
    signature: Bytes,
}

impl HavenLocator {
    pub fn new(
        identity_sk: IdentitySecret,
        onion_pk: OnionPublic,
        rendezvous_fingerprint: Fingerprint,
    ) -> HavenLocator {
        let identity_pk = identity_sk.public();
        let signable = HavenLocator {
            identity_pk,
            onion_pk,
            rendezvous_fingerprint,
            signature: Bytes::new(),
        };

        let signature = identity_sk.sign(&signable.stdcode());

        HavenLocator {
            identity_pk,
            onion_pk,
            rendezvous_fingerprint,
            signature,
        }
    }

    pub fn id_pk(&self) -> IdentityPublic {
        self.identity_pk
    }

    pub fn onion_pk(&self) -> OnionPublic {
        self.onion_pk
    }

    pub fn rendezvous_fp(&self) -> Fingerprint {
        self.rendezvous_fingerprint
    }

    pub fn signature(&self) -> Bytes {
        self.signature.clone()
    }

    pub fn signable(&self) -> HavenLocator {
        HavenLocator {
            identity_pk: self.identity_pk,
            onion_pk: self.onion_pk,
            rendezvous_fingerprint: self.rendezvous_fingerprint,
            signature: Bytes::new(),
        }
    }
}
