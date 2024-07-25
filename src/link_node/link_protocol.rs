use std::collections::HashMap;

use async_trait::async_trait;
use bytes::Bytes;

use earendil_crypt::{RelayFingerprint, RelayIdentityPublic};
use earendil_topology::{AdjacencyDescriptor, ExitInfo, ExitRegistry, IdentityDescriptor};
use nanorpc::nanorpc_derive;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use thiserror::Error;

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

    /// Send a chat message to the other end of the link.
    async fn push_chat(&self, msg: String) -> Result<(), LinkRpcErr>;

    /// Gets a one-time token to use in payment proofs for anti-double-spending
    async fn get_ott(&self) -> Result<String, LinkRpcErr>;

    async fn send_payment_proof(
        &self,
        amount: u64,
        paysystem_name: String,
        proof: String,
    ) -> Result<(), LinkRpcErr>;
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

/// Errors that can occur during a Link RPC call.
#[derive(Error, Debug, Serialize, Deserialize)]
pub enum LinkRpcErr {
    #[error("push chat failed")]
    PushChatFailed,
    #[error("invalid payment proof")]
    InvalidPaymentProof,
    #[error("unaccepted payment system")]
    UnacceptedPaysystem,
    #[error("payment verification failed: {0}")]
    PaymentVerificationFailed(String),
    #[error("invalid payment_id")]
    InvalidPaymentId,
    #[error("internal server error: {0}")]
    InternalServerError(String),
}
