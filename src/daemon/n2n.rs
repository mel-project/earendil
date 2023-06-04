use async_trait::async_trait;
use bytes::Bytes;

use earendil_topology::IdentityPublic;
use nanorpc::nanorpc_derive;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sosistab2::MuxPublic;

#[nanorpc_derive]
#[async_trait]
pub trait N2nProtocol {
    /// Challenge the other end to prove their identity.
    async fn authenticate(&self) -> AuthResponse;

    /// A method that returns some random info. Used for keepalive and statistics.
    async fn info(&self) -> InfoResponse;
}

/// Response to an authentication challenge.
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct AuthResponse {
    #[serde_as(as = "serde_with::hex::Hex")]
    pub full_pk: IdentityPublic,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub binding_sig: Bytes,
}

/// Response to an info request.
#[derive(Serialize, Deserialize)]
pub struct InfoResponse {
    pub version: String,
}

impl AuthResponse {
    /// Verifies against the supposed other-side sosistab2 public key.
    pub fn verify(&self, peer_pk: &MuxPublic) -> bool {
        let to_sign = blake3::keyed_hash(b"n2n_auth________________________", peer_pk.as_bytes());
        self.full_pk.verify(to_sign.as_bytes(), &self.binding_sig)
    }
}
