use crate::commands::{ChatCommands, ControlCommands};
use crate::socket::Endpoint;
use crate::{daemon::ControlProtErr, haven_util::HavenLocator};
use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use earendil_crypt::{Fingerprint, IdentitySecret};
use earendil_packet::{
    crypt::{OnionPublic, OnionSecret},
    Dock, PacketConstructError,
};
use nanorpc::nanorpc_derive;
use nanorpc_http::client::HttpRpcTransport;
use parking_lot::Mutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use smol::channel::Sender;
use smol::Timer;
use smolscale::reaper::TaskReaper;
use std::io::{stdin, stdout, Write};
use std::marker::Send;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
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
                Err(e) => println!("error receiving message: {e}"),
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
        ControlCommands::GraphDump { human } => {
            let res = client.graph_dump(human).await?;
            println!("{res}");
        }
        ControlCommands::MyRoutes => {
            let routes = client.my_routes().await?;
            println!("{}", serde_yaml::to_string(&routes)?);
        }
        ControlCommands::HavensInfo => {
            let havens_info = client.havens_info().await?;
            for info in havens_info {
                println!("{} - {}", info.0, info.1);
            }
        }
        ControlCommands::ListChats => {
            println!("Fingerprint\t\tLastActivity\tLast Message");
            let res = client.list_chats().await?;
            println!("{res}");
        }
        ControlCommands::GetChat { neighbor } => {
            let entries = client.get_chat(neighbor).await?;
            for (is_mine, text, time) in entries {
                let arrow = if is_mine { "->" } else { "<-" };
                let datetime: DateTime<Utc> = time.into();

                println!(
                    "[{}] {} {}",
                    datetime.format("%Y-%m-%d %H:%M:%S"),
                    arrow,
                    text
                );
            }
        }
        ControlCommands::SendChatMsg { dest, msg } => {
            client.send_chat_msg(dest, msg).await?;
        }
        ControlCommands::Chat { chat_command: cmd } => match cmd {
            ChatCommands::List => {
                println!("Fingerprint\t\tLastActivity\tLast Message");
                let res = client.list_chats().await?;
                println!("{res}");
            }
            ChatCommands::Start { fingerprint } => {
                // TODO: first, list stored chat history in the correct format (maybe use a
                // modified get_chat)

                // start accepting new messages
                println!("<starting chat with {}>", fingerprint);

                let (request_tx, request_rx) = channel::unbounded::<ControlClientRequest>();

                let client = Arc::new(Mutex::new(client));

                thread::spawn(move || {
                    while let Ok(request) = request_rx.recv() {
                        match request {
                            ControlClientRequest::GetChat(fingerprint, response_tx) => {
                                let result = control_client.lock().unwrap().get_chat(fingerprint);
                                // Send the result back through the provided response channel
                                let _ = response_tx.send(result);
                            } // Other request variants could be added here
                        }
                    }
                });

                loop {
                    // Print the prompt
                    print!("-> ");
                    stdout().flush().unwrap(); // Make sure the prompt is displayed

                    // Read a line of input from the user
                    let mut message = String::new();
                    stdin()
                        .read_line(&mut message)
                        .expect("Failed to read line");

                    // Trim the newline character from the input
                    let message = message.trim();

                    // If the user has entered a message, process and display it
                    if !message.is_empty() {
                        // Get the current timestamp
                        let timestamp = current_time_stamp();

                        // Display the message with the timestamp
                        println!("{} [{}]", message, timestamp);

                        // send message
                        client
                            .lock()
                            .send_chat_msg(fingerprint, message.to_string())
                            .await?;
                    }
                }
            }
        },
    }
    Ok(())
}

fn current_time_stamp() -> String {
    // Get the current time as a SystemTime object
    let now = SystemTime::now();

    // Convert the SystemTime object to a DateTime object in the local timezone
    let datetime: chrono::DateTime<chrono::Local> = now.into();

    // Format the DateTime object as a string
    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
}

// Define a message type for requests
enum ControlClientRequest {
    GetChat(
        String,
        Sender<Result<Vec<(bool, String, i64)>, anyhow::Error>>,
    ),
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

    async fn havens_info(&self) -> Vec<(String, String)>;

    async fn send_message(&self, args: SendMessageArgs) -> Result<(), ControlProtErr>;

    async fn recv_message(&self, socket_id: String) -> Result<(Bytes, Endpoint), ControlProtErr>;

    async fn send_global_rpc(
        &self,
        args: GlobalRpcArgs,
    ) -> Result<serde_json::Value, GlobalRpcError>;

    async fn graph_dump(&self, human: bool) -> String;

    async fn my_routes(&self) -> serde_json::Value;

    async fn insert_rendezvous(&self, locator: HavenLocator) -> Result<(), DhtError>;

    async fn get_rendezvous(
        &self,
        fingerprint: Fingerprint,
    ) -> Result<Option<HavenLocator>, DhtError>;

    async fn list_chats(&self) -> String;

    async fn get_chat(&self, neigh: Fingerprint) -> Vec<(bool, String, SystemTime)>;

    async fn send_chat_msg(&self, dest: Fingerprint, msg: String);
}

#[derive(Error, Serialize, Deserialize, Debug)]
pub enum SendMessageError {
    #[error("no route to the given destination {0}")]
    NoRoute(Fingerprint),
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
    #[error("failed to verify descriptor retrieved from DHT")]
    VerifyFailed,
    #[error("network failed: {0}")]
    NetworkFailure(String),
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
