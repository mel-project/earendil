use async_trait::async_trait;
use bytes::Bytes;

use earendil_topology::{IdentityPublic, IdentitySecret};
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

const MAGIC_VALUE: &[u8; 32] = b"n2n_auth________________________";

impl AuthResponse {
    /// Create a new AuthResponse instance.
    pub fn new(my_identity: &IdentitySecret, my_pk: &MuxPublic) -> Self {
        let to_sign = blake3::keyed_hash(MAGIC_VALUE, my_pk.as_bytes());
        let binding_sig = my_identity.sign(to_sign.as_bytes());

        AuthResponse {
            full_pk: my_identity.public(),
            binding_sig: Bytes::from(binding_sig.as_ref().to_vec()),
        }
    }

    /// Verifies against the supposed other-side sosistab2 public key.
    pub fn verify(&self, peer_pk: &MuxPublic) -> bool {
        let to_sign = blake3::keyed_hash(MAGIC_VALUE, peer_pk.as_bytes());
        self.full_pk.verify(to_sign.as_bytes(), &self.binding_sig)
    }
}
