use async_trait::async_trait;

use earendil_packet::Fingerprint;
use nanorpc::nanorpc_derive;
use nanorpc_http::client::HttpRpcTransport;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use thiserror::Error;

use crate::ControlCommands;

pub async fn main_control(control_command: ControlCommands) -> anyhow::Result<()> {
    let conn = ControlClient::from(HttpRpcTransport::new("127.0.0.1:18964".parse().unwrap()));
    match control_command {
        ControlCommands::SendMessage {
            destination,
            message: _,
        } => {
            conn.send_message(SendMessageArgs {
                destination,
                content: [0; 8192],
            })
            .await??;
        }
        ControlCommands::GraphDump => {
            let res = conn.graph_dump().await?;
            println!("{res}");
        }
    }
    Ok(())
}

#[nanorpc_derive]
#[async_trait]
pub trait ControlProtocol {
    async fn send_message(&self, args: SendMessageArgs) -> Result<(), SendMessageError>;

    async fn graph_dump(&self) -> String;
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
