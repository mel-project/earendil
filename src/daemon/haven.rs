use earendil_crypt::{Fingerprint, IdentityPublic};
use earendil_packet::crypt::OnionPublic;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct HavenLocator {
    full_pk: IdentityPublic,
    onion_pk: OnionPublic,
    rendezvous_relay_fingerprint: Fingerprint,
}
