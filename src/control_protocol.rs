use std::{net::SocketAddr, time::Duration};

use anyhow::Context;
use async_trait::async_trait;

use bytes::Bytes;

use earendil_crypt::Fingerprint;
use earendil_packet::{Dock, Message, PacketConstructError};
use nanorpc::nanorpc_derive;
use nanorpc_http::client::HttpRpcTransport;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{daemon::haven::HavenLocator, ControlCommands};
use thiserror::Error;

pub async fn main_control(
    control_command: ControlCommands,
    connect: SocketAddr,
) -> anyhow::Result<()> {
    let conn = ControlClient::from(HttpRpcTransport::new(connect));
    match control_command {
        ControlCommands::SendMessage {
            id,
            source_dock,
            dest_dock,
            destination,
            message,
        } => {
            conn.send_message(SendMessageArgs {
                id,
                source_dock,
                dest_dock,
                destination,
                content: Bytes::copy_from_slice(message.as_bytes()),
            })
            .await??;
        }
        ControlCommands::GlobalRpc {
            id,

            destination,
            method,
            args,
        } => {
            let args: Result<Vec<serde_json::Value>, _> =
                args.into_iter().map(|a| serde_yaml::from_str(&a)).collect();
            let args = args.context("arguments not YAML")?;
            let res = conn
                .send_global_rpc(GlobalRpcArgs {
                    id,

                    destination,
                    method,
                    args,
                })
                .await??;
            println!("{res}");
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

    async fn send_global_rpc(
        &self,
        args: GlobalRpcArgs,
    ) -> Result<serde_json::Value, GlobalRpcError>;

    async fn graph_dump(&self) -> String;

    async fn my_routes(&self) -> serde_json::Value;

    async fn recv_message(&self) -> Option<(Message, Fingerprint)>;

    async fn insert_rendezvous(
        &self,
        fingerprint: Fingerprint,
        locator: HavenLocator,
    ) -> Result<(), DhtError>;

    async fn get_rendezvous(
        &self,
        fingerprint: Fingerprint,
    ) -> Result<Option<HavenLocator>, DhtError>;
}

#[derive(Error, Serialize, Deserialize, Debug)]
pub enum SendMessageError {
    #[error("no route to the given destination")]
    NoRoute,
    #[error(transparent)]
    PacketConstructError(#[from] PacketConstructError),
    #[error("no onion public key for fingerprint {0}")]
    NoOnionPublic(Fingerprint),
    #[error("failed to construct reply block")]
    ReplyBlockFailed,
    #[error("cannot use anonymous id to communicate with anonymous id")]
    NoAnonId,
}

#[derive(Error, Serialize, Deserialize, Debug)]
pub enum DhtError {
    #[error("serialization error")]
    Serde,
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct SendMessageArgs {
    pub id: Option<String>,
    pub source_dock: Dock,
    pub dest_dock: Dock,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub destination: Fingerprint,
    #[serde_as(as = "serde_with::base64::Base64")]
    pub content: Bytes,
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct GlobalRpcArgs {
    pub id: Option<String>,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub destination: Fingerprint,
    pub method: String,
    pub args: Vec<serde_json::Value>,
}

#[derive(Error, Serialize, Deserialize, Debug)]
pub enum GlobalRpcError {
    #[error("error sending GlobalRpc request")]
    SendError,
}
