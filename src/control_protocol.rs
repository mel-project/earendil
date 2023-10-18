use std::{net::SocketAddr, time::Duration};

use async_trait::async_trait;

use bytes::Bytes;

use earendil_crypt::Fingerprint;
use nanorpc::nanorpc_derive;
use nanorpc_http::client::HttpRpcTransport;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use thiserror::Error;

use crate::ControlCommands;

pub async fn main_control(
    control_command: ControlCommands,
    connect: SocketAddr,
) -> anyhow::Result<()> {
    let conn = ControlClient::from(HttpRpcTransport::new(connect));
    match control_command {
        ControlCommands::SendMessage {
            destination,
            message,
        } => {
            conn.send_message(SendMessageArgs {
                destination,
                content: Bytes::copy_from_slice(message.as_bytes()),
            })
            .await??;
        }
        ControlCommands::GraphDump => {
            let res = conn.graph_dump().await?;
            println!("{res}");
        }
        ControlCommands::RecvMessage => loop {
            if let Some((msg, src)) = conn.recv_message().await? {
                println!("{:?} from {src}", msg);
                break;
            }
            smol::Timer::after(Duration::from_millis(100)).await;
        },
        ControlCommands::MyRoutes => {
            let routes = conn.my_routes().await?;
            println!("{}", serde_yaml::to_string(&routes)?);
        }
    }
    Ok(())
}

#[nanorpc_derive]
#[async_trait]
pub trait ControlProtocol {
    async fn send_message(&self, args: SendMessageArgs) -> Result<(), SendMessageError>;

    async fn graph_dump(&self) -> String;

    async fn my_routes(&self) -> serde_json::Value;

    async fn recv_message(&self) -> Option<(Bytes, Fingerprint)>;
}

#[derive(Error, Serialize, Deserialize, Debug)]
pub enum SendMessageError {
    #[error("no route to the given destination")]
    NoRoute,
    #[error("destination way too far")]
    TooFar,
    #[error("message is too big")]
    MessageTooBig,
    #[error("no onion public key for fingerprint {0}")]
    NoOnionPublic(Fingerprint),
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct SendMessageArgs {
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub destination: Fingerprint,
    #[serde_as(as = "serde_with::base64::Base64")]
    pub content: Bytes,
}
