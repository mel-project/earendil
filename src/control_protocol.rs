use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use earendil_crypt::{AnonEndpoint, HavenFingerprint, RelayFingerprint};
use earendil_packet::PacketConstructError;
use nanorpc::nanorpc_derive;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use thiserror::Error;

use crate::{v2h_node::HavenLocator, ChatEntry, NodeId};

#[nanorpc_derive]
#[async_trait]
pub trait ControlProtocol {
    async fn havens_info(&self) -> Result<Vec<(String, String)>, ConfigError>;

    async fn my_routes(&self) -> serde_json::Value;

    async fn relay_graphviz(&self) -> String; // graphviz

    async fn relay_graph_info(&self) -> RelayGraphInfo;

    // ------------- functionality to test GlobalRpc --------------
    async fn send_global_rpc(
        &self,
        args: GlobalRpcArgs,
    ) -> Result<serde_json::Value, GlobalRpcError>;

    async fn insert_rendezvous(&self, locator: HavenLocator);

    async fn get_rendezvous(
        &self,
        fingerprint: HavenFingerprint,
    ) -> Result<Option<HavenLocator>, DhtError>;

    // ---------------- chat-related functionality -----------------
    async fn list_neighbors(&self) -> Vec<NodeId>;

    async fn list_chats(&self) -> Result<HashMap<String, (Option<ChatEntry>, u32)>, ChatError>;

    // true = outgoing, false = incoming
    async fn get_chat(&self, neighbor: String) -> Result<Vec<ChatEntry>, ChatError>;

    async fn send_chat(&self, dest: String, msg: String) -> Result<(), ChatError>;

    async fn timeseries_stats(&self, key: String, start: i64, end: i64) -> Vec<(i64, f64)>;

    async fn get_debt_summary(&self) -> Result<HashMap<String, f64>, DebtError>;

    async fn get_debt(&self, neighbor: String) -> Result<f64, DebtError>;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RelayGraphInfo {
    pub my_fingerprint: Option<RelayFingerprint>,
    pub relays: Vec<RelayFingerprint>,
    pub adjacencies: Vec<(RelayFingerprint, RelayFingerprint)>,
    pub neighbors: Vec<NodeId>,
}

#[derive(Error, Serialize, Deserialize, Debug)]
pub enum SendMessageError {
    #[error("no route to the given destination {0}")]
    NoRoute(RelayFingerprint),
    #[error(transparent)]
    PacketConstructError(#[from] PacketConstructError),
    #[error("no onion public key for fingerprint {0}")]
    NoOnionPublic(RelayFingerprint),
    #[error("failed to construct reply block {0}")]
    ReplyBlockFailed(String),
    #[error("cannot use anonymous id to communicate with anonymous id")]
    NoAnonId,
    #[error("mismatched nodes")]
    MismatchedNodes,
    #[error("client id not found")]
    NoClientId,
    #[error("no reply blocks available for {0}")]
    NoReplyBlocks(AnonEndpoint),
}

#[derive(Error, Serialize, Deserialize, Debug)]
pub enum DhtError {
    #[error("network failed: {0}")]
    DhtGetFailed(String),
    #[error("failed to verify descriptor retrieved from DHT")]
    VerifyFailed,
    #[error("network failed: {0}")]
    NetworkFailure(String),
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct GlobalRpcArgs {
    pub id: Option<String>,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub destination: RelayFingerprint,
    pub method: String,
    pub args: Vec<serde_json::Value>,
}

#[derive(Error, Serialize, Deserialize, Debug)]
pub enum GlobalRpcError {
    #[error("error sending GlobalRpc request")]
    SendError,
}

#[derive(Error, Serialize, Deserialize, Debug)]
pub enum ChatError {
    #[error("error getting conversation {0}")]
    Get(String),
    #[error("error sending chat message {0}")]
    Send(String),
    #[error("database error: {0}")]
    Db(String),
}

#[derive(Error, Serialize, Deserialize, Debug)]
pub enum DebtError {
    #[error("error getting debt summary")]
    Summary,
    #[error("error getting debt for neighbor {0}")]
    Get(String),
}

#[derive(Error, Serialize, Deserialize, Debug)]
pub enum ConfigError {
    #[error("{0}")]
    Error(String),
}
