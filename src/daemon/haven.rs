use earendil_crypt::{Fingerprint, IdentityPublic};
use earendil_packet::crypt::OnionPublic;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct HavenLocator {
    identity_pk: IdentityPublic,
    onion_pk: OnionPublic,
    rendezvous_fingerprint: Fingerprint,
}
