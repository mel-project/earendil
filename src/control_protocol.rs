use crate::commands::ControlCommands;
use crate::socket::Endpoint;
use crate::{daemon::ControlProtErr, haven::HavenLocator};
use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use earendil_crypt::{Fingerprint, IdentitySecret, VerifyError};
use earendil_packet::{
    crypt::{OnionPublic, OnionSecret},
    Dock, PacketConstructError,
};
use nanorpc::nanorpc_derive;
use nanorpc_http::client::HttpRpcTransport;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::marker::Send;
use std::{net::SocketAddr, str::FromStr};
use thiserror::Error;

pub async fn main_control(
    control_command: ControlCommands,
    connect: SocketAddr,
) -> anyhow::Result<()> {
    let client = ControlClient::from(HttpRpcTransport::new(connect));
    match control_command {
        ControlCommands::BindN2r {
            skt_id,
            anon_id,
            dock,
        } => {
            client.bind_n2r(skt_id, anon_id, dock).await?;
        }
        ControlCommands::BindHaven {
            skt_id,
            anon_id,
            dock,
            rendezvous,
        } => {
            client.bind_haven(skt_id, anon_id, dock, rendezvous).await?;
        }
        ControlCommands::SktInfo { skt_id } => {
            let skt_info = client.skt_info(skt_id).await??;
            println!("{skt_info}")
        }
        ControlCommands::SendMsg {
            skt_id: socket_id,
            dest: destination,
            msg: message,
        } => {
            client
                .send_message(SendMessageArgs {
                    socket_id,
                    destination,
                    content: Bytes::copy_from_slice(message.as_bytes()),
                })
                .await??;
        }
        ControlCommands::RecvMsg { skt_id: socket_id } => {
            match client.recv_message(socket_id.clone()).await? {
                Ok((msg, src)) => println!("{:?} from {}", msg, src),
                Err(e) => println!("ERROR receiving message: {e}"),
            }
        }
        ControlCommands::GlobalRpc {
            id,
            dest: destination,
            method,
            args,
        } => {
            let args: Result<Vec<serde_json::Value>, _> =
                args.into_iter().map(|a| serde_yaml::from_str(&a)).collect();
            let args = args.context("arguments not YAML")?;
            let res = client
                .send_global_rpc(GlobalRpcArgs {
                    id,

                    destination,
                    method,
                    args,
                })
                .await??;
            println!("{res}");
        }
        ControlCommands::InsertRendezvous {
            identity_sk,
            onion_pk,
            rendezvous_fingerprint,
        } => {
            let locator = HavenLocator::new(
                IdentitySecret::from_str(&identity_sk)?,
                OnionPublic::from_str(&onion_pk)?,
                rendezvous_fingerprint,
            );
            client.insert_rendezvous(locator).await??;
        }
        ControlCommands::GetRendezvous { key } => {
            let locator = client.get_rendezvous(key).await??;
            if let Some(locator) = locator {
                println!("{:?}", locator);
            } else {
                println!("No haven locator found for fingerprint {key}")
            }
        }
        ControlCommands::RendezvousHavenTest => {
            let mut fingerprint_bytes = [0; 20];
            rand::thread_rng().fill_bytes(&mut fingerprint_bytes);
            let fingerprint = Fingerprint::from_bytes(&fingerprint_bytes);
            let id_sk = IdentitySecret::generate();
            let id_pk = id_sk.public();
            let locator = HavenLocator::new(id_sk, OnionSecret::generate().public(), fingerprint);
            eprintln!("created haven locator: {:?}", &locator);

            client.insert_rendezvous(locator.clone()).await??;
            eprintln!("inserted haven locator... sleeping for 5s");

            if let Some(fetched_locator) = client.get_rendezvous(id_pk.fingerprint()).await?? {
                eprintln!("got haven locator: {:?}", &fetched_locator);
                assert_eq!(locator.rendezvous_point, fetched_locator.rendezvous_point);
            } else {
                eprintln!("oh no couldn't find locator");
            }
        }
        ControlCommands::GraphDump => {
            let res = client.graph_dump().await?;
            println!("{res}");
        }
        ControlCommands::MyRoutes => {
            let routes = client.my_routes().await?;
            println!("{}", serde_yaml::to_string(&routes)?);
        }
    }
    Ok(())
}

#[nanorpc_derive]
#[async_trait]
pub trait ControlProtocol {
    async fn bind_n2r(&self, socket_id: String, anon_id: Option<String>, dock: Option<Dock>);

    async fn bind_haven(
        &self,
        socket_id: String,
        anon_id: Option<String>,
        dock: Option<Dock>,
        rendezvous_point: Option<Fingerprint>,
    );

    async fn skt_info(&self, skt_id: String) -> Result<Endpoint, ControlProtErr>;

    async fn send_message(&self, args: SendMessageArgs) -> Result<(), ControlProtErr>;

    async fn recv_message(&self, socket_id: String) -> Result<(Bytes, Endpoint), ControlProtErr>;

    async fn send_global_rpc(
        &self,
        args: GlobalRpcArgs,
    ) -> Result<serde_json::Value, GlobalRpcError>;

    async fn graph_dump(&self) -> String;

    async fn my_routes(&self) -> serde_json::Value;

    async fn insert_rendezvous(&self, locator: HavenLocator) -> Result<(), DhtError>;

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
    #[error(transparent)]
    Verification(#[from] VerifyError),
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct SendMessageArgs {
    pub socket_id: String,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub destination: Endpoint,
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
