use async_trait::async_trait;
use bytes::Bytes;
use earendil_packet::Fingerprint;
use nanorpc::nanorpc_derive;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use thiserror::Error;

#[nanorpc_derive]
#[async_trait]
pub trait ControlProtocol {
    async fn send_message(&self, args: SendMessageArgs) -> Result<(), SendMessageError>;
}

#[derive(Error, Serialize, Deserialize, Debug)]
pub enum SendMessageError {
    #[error("no route to the given destination")]
    NoRoute,
    #[error("destination way too far")]
    TooFar,
    #[error("no onion public key for fingerprint {0}")]
    NoOnionPublic(Fingerprint),
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct SendMessageArgs {
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub destination: Fingerprint,
    #[serde_as(as = "serde_with::base64::Base64")]
    pub content: [u8; 8192],
}
