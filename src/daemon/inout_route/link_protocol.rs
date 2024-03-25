use async_trait::async_trait;
use bytes::Bytes;

use earendil_crypt::{RelayFingerprint, RelayIdentityPublic};
use earendil_topology::{AdjacencyDescriptor, IdentityDescriptor};
use nanorpc::nanorpc_derive;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::settlement::{Seed, SettlementRequest, SettlementResponse};

#[nanorpc_derive]
#[async_trait]
pub trait LinkProtocol {
    /// A method that returns some random info. Used for keepalive and statistics.
    async fn info(&self) -> InfoResponse;

    /// Asks the other end to complete an adjacency descriptor. Returns None to indicate refusal. This is called by the "left-hand" neighbor to ask the "right-hand" neighbor to sign.
    async fn sign_adjacency(
        &self,
        left_incomplete: AdjacencyDescriptor,
    ) -> Option<AdjacencyDescriptor>;

    /// Gets the identity of a particular fingerprint. Returns None if that identity is not known to this node.
    async fn identity(&self, fp: RelayFingerprint) -> Option<IdentityDescriptor>;

    /// Gets all the adjacency-descriptors adjacent to the given fingerprints. This is called repeatedly to eventually discover the entire graph.
    async fn adjacencies(&self, fps: Vec<RelayFingerprint>) -> Vec<AdjacencyDescriptor>;

    /// Sends a settlement request and waits until a response is received or the call times out.
    async fn start_settlement(&self, req: SettlementRequest) -> Option<SettlementResponse>;

    /// Send a chat message to the other end of the link.
    async fn push_chat(&self, msg: String);

    /// Request a MelPoW seed (used to create an automatic payment proof).
    async fn request_seed(&self) -> Option<Seed>;
}

/// Response to an authentication challenge.
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct AuthResponse {
    #[serde_as(as = "serde_with::hex::Hex")]
    pub full_pk: RelayIdentityPublic,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub binding_sig: Bytes,
}

/// Response to an info request.
#[derive(Serialize, Deserialize)]
pub struct InfoResponse {
    pub version: String,
}
