use crate::{
    commands::{ChatCommand, ControlCommand},
    daemon::ChatEntry,
    haven::HavenLocator,
};
use anyhow::Context;
use async_trait::async_trait;

use chrono::{DateTime, Utc};
use colored::{ColoredString, Colorize};
use earendil_crypt::{
    AnonEndpoint, ClientId, HavenFingerprint, HavenIdentitySecret, RelayFingerprint,
};
use earendil_packet::{crypt::DhPublic, PacketConstructError};
use either::Either;
use nanorpc::nanorpc_derive;
use nanorpc_http::client::HttpRpcTransport;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use smol::Timer;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use std::{io::Write, marker::Send};
use std::{net::SocketAddr, str::FromStr};
use thiserror::Error;

pub async fn main_control(
    control_command: ControlCommand,
    connect: SocketAddr,
) -> anyhow::Result<()> {
    let control = ControlClient::from(HttpRpcTransport::new(connect));
    match control_command {
        ControlCommand::GlobalRpc {
            id,
            dest: destination,
            method,
            args,
        } => {
            let args: Result<Vec<serde_json::Value>, _> =
                args.into_iter().map(|a| serde_yaml::from_str(&a)).collect();
            let args = args.context("arguments not YAML")?;
            let res = control
                .send_global_rpc(GlobalRpcArgs {
                    id,
                    destination,
                    method,
                    args,
                })
                .await??;
            println!("{res}");
        }
        ControlCommand::InsertRendezvous {
            identity_sk,
            onion_pk,
            rendezvous_fingerprint,
        } => {
            let locator = HavenLocator::new(
                HavenIdentitySecret::from_str(&identity_sk)?,
                DhPublic::from_str(&onion_pk)?,
                rendezvous_fingerprint,
            );
            control.insert_rendezvous(locator).await??;
        }
        ControlCommand::GetRendezvous { key } => {
            let locator = control.get_rendezvous(key).await??;
            if let Some(locator) = locator {
                println!("{:?}", locator);
            } else {
                println!("No haven locator found for fingerprint {key}")
            }
        }
        ControlCommand::RelayGraphviz => {
            let res = control.relay_graphviz().await?;
            println!("{res}");
        }
        ControlCommand::MyRoutes => {
            let routes = control.my_routes().await?;
            println!("{}", serde_yaml::to_string(&routes)?);
        }
        ControlCommand::HavensInfo => {
            for info in control.havens_info().await?? {
                println!("{} - {}", info.0, info.1);
            }
        }
        ControlCommand::Chat { chat_command } => match chat_command {
            ChatCommand::List => {
                let divider = "+-------------------------------------+---------------+-----------------------------------+";
                let chats = control.list_chats().await?;
                println!("{divider}");
                println!("| Neighbor                            | # of Messages | Last chat                         |");
                println!("{divider}");

                for (neigh, (maybe_entry, num_msgs)) in chats {
                    let neigh = if neigh.len() > 32 {
                        neigh[..32].to_owned() + "..."
                    } else {
                        neigh
                    };
                    let (text, timestamp) = if let Some(entry) = maybe_entry {
                        (entry.text, create_timestamp(entry.time))
                    } else {
                        (
                            "                               ".to_owned(),
                            "               ".to_owned(),
                        )
                    };
                    println!(
                        "| {:<35} | {:<13} | {} {}",
                        neigh, num_msgs, text, timestamp
                    );
                    println!("{divider}");
                }
            }
            ChatCommand::Start { neighbor } => {
                let mut displayed: HashSet<(bool, String, SystemTime)> = HashSet::new();
                let control = Arc::new(control);
                let control_clone = control.clone();
                let neighbor_clone = neighbor.clone();

                let _listen_loop = smolscale::spawn(async move {
                    loop {
                        let msgs = match control.get_chat(neighbor.clone()).await {
                            Ok(Ok(msgs)) => msgs,
                            Ok(Err(e)) => {
                                println!("error fetching messages: {:?}", e);
                                Timer::after(Duration::from_secs(1)).await;
                                continue;
                            }
                            Err(control_err) => {
                                println!("control protocol error: {:?}", control_err);
                                Timer::after(Duration::from_secs(1)).await;
                                continue;
                            }
                        };
                        for (is_mine, text, time) in msgs {
                            let msg = (is_mine, text.clone(), time);
                            if !displayed.contains(&msg) {
                                println!("{}", pretty_entry(is_mine, text, time));
                                displayed.insert(msg);
                            }
                        }
                    }
                });

                loop {
                    let _ = std::io::stdout().flush();
                    let message = smol::unblock(|| {
                        let mut message = String::new();
                        std::io::stdin()
                            .read_line(&mut message)
                            .expect("Failed to read line");

                        message.trim().to_string()
                    })
                    .await;

                    if !message.is_empty() {
                        let msg = message.to_string();
                        match control_clone.send_chat(neighbor_clone.clone(), msg).await? {
                            Ok(_) => continue,
                            Err(e) => println!("ERROR: {e}"),
                        }
                    }
                }
            }
            ChatCommand::Get { src } => {
                let entries = control.get_chat(src).await??;
                for (is_mine, text, time) in entries {
                    println!("{}", pretty_entry(is_mine, text, time));
                }
            }
            ChatCommand::Send { dest, msg } => {
                control.send_chat(dest, msg).await??;
            }
        },
    }
    Ok(())
}

fn earendil_blue(string: &str) -> ColoredString {
    string
        .custom_color(colored::CustomColor {
            r: 0,
            g: 129,
            b: 162,
        })
        .bold()
}

fn left_arrow() -> ColoredString {
    earendil_blue("<-")
}

fn right_arrow() -> ColoredString {
    earendil_blue("->")
}

fn pretty_entry(is_mine: bool, text: String, time: SystemTime) -> String {
    let arrow = if is_mine { right_arrow() } else { left_arrow() };

    format!("{} {} {}", arrow, text, pretty_time(time))
}

fn pretty_time(time: SystemTime) -> ColoredString {
    let datetime: DateTime<Utc> = time.into();

    format!("[{}]", datetime.format("%Y-%m-%d %H:%M:%S")).bright_yellow()
}

#[nanorpc_derive]
#[async_trait]
pub trait ControlProtocol {
    async fn havens_info(&self) -> Result<Vec<(String, String)>, ConfigError>;

    async fn send_global_rpc(
        &self,
        args: GlobalRpcArgs,
    ) -> Result<serde_json::Value, GlobalRpcError>;

    async fn relay_graphviz(&self) -> String; // graphviz

    async fn my_routes(&self) -> serde_json::Value;

    async fn insert_rendezvous(&self, locator: HavenLocator) -> Result<(), DhtError>;

    async fn get_rendezvous(
        &self,
        fingerprint: HavenFingerprint,
    ) -> Result<Option<HavenLocator>, DhtError>;

    async fn list_neighbors(&self) -> Vec<Either<ClientId, RelayFingerprint>>;

    async fn list_chats(&self) -> HashMap<String, (Option<ChatEntry>, u32)>;

    // true = outgoing, false = incoming
    async fn get_chat(&self, src: String) -> Result<Vec<(bool, String, SystemTime)>, ChatError>;

    async fn send_chat(&self, dest: String, msg: String) -> Result<(), ChatError>;
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
}

#[derive(Error, Serialize, Deserialize, Debug)]
pub enum ConfigError {
    #[error("{0}")]
    Error(String),
}

fn create_timestamp(now: SystemTime) -> String {
    let datetime: chrono::DateTime<chrono::Local> = now.into();

    format!("[{}]", datetime.format("%Y-%m-%d %H:%M:%S"))
}
