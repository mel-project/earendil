use async_trait::async_trait;
use bytes::Bytes;

use earendil_crypt::{Fingerprint, IdentityPublic, IdentitySecret};
use earendil_topology::{AdjacencyDescriptor, IdentityDescriptor};
use nanorpc::nanorpc_derive;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sosistab2::MuxPublic;

#[nanorpc_derive]
#[async_trait]
pub trait LinkProtocol {
    /// Challenge the other end to prove their identity.
    async fn authenticate(&self) -> AuthResponse;

    /// A method that returns some random info. Used for keepalive and statistics.
    async fn info(&self) -> InfoResponse;

    /// Asks the other end to complete an adjacency descriptor. Returns None to indicate refusal. This is called by the "left-hand" neighbor to ask the "right-hand" neighbor to sign.
    async fn sign_adjacency(
        &self,
        left_incomplete: AdjacencyDescriptor,
    ) -> Option<AdjacencyDescriptor>;

    /// Gets the identity of a particular fingerprint. Returns None if that identity is not known to this node.
    async fn identity(&self, fp: Fingerprint) -> Option<IdentityDescriptor>;

    /// Gets all the adjacency-descriptors adjacent to the given fingerprints. This is called repeatedly to eventually discover the entire graph.
    async fn adjacencies(&self, fps: Vec<Fingerprint>) -> Vec<AdjacencyDescriptor>;
    /// pushes how much it will cost the neighbor to send me a packet, denominated in microMEL/packet
    /// debt_limit = max amount neighbor is allowed to owe me before I stop forwarding their packets
    async fn push_price(&self, price: u64, debt_limit: u64);

    /// Send a chat message to the other end of the link.
    async fn push_chat(&self, msg: String);
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
    pub fn verify(&self, peer_pk: &MuxPublic) -> Result<(), earendil_crypt::VerifyError> {
        let to_sign = blake3::keyed_hash(MAGIC_VALUE, peer_pk.as_bytes());
        self.full_pk.verify(to_sign.as_bytes(), &self.binding_sig)
    }
}
