use crate::commands::{ChatCommand, ControlCommand};
use crate::socket::RelayEndpoint;
use crate::{daemon::ControlProtErr, haven_util::HavenLocator};
use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use colored::{ColoredString, Colorize};
use earendil_crypt::{
    AnonEndpoint, ClientId, HavenFingerprint, HavenIdentitySecret, RelayFingerprint,
};
use earendil_packet::{
    crypt::{OnionPublic, OnionSecret},
    Dock, PacketConstructError,
};
use nanorpc::nanorpc_derive;
use nanorpc_http::client::HttpRpcTransport;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use smol::Timer;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use std::{io::Write, marker::Send};
use std::{net::SocketAddr, str::FromStr};
use thiserror::Error;

pub async fn main_control(
    control_command: ControlCommand,
    connect: SocketAddr,
) -> anyhow::Result<()> {
    let link = ControlClient::from(HttpRpcTransport::new(connect));
    match control_command {
        ControlCommand::BindN2r {
            skt_id,
            anon_id,
            dock,
        } => {
            link.bind_n2r(skt_id, anon_id, dock).await?;
        }
        ControlCommand::BindHaven {
            skt_id,
            anon_id,
            dock,
            rendezvous,
        } => {
            link.bind_haven(skt_id, anon_id, dock, rendezvous).await?;
        }
        ControlCommand::SktInfo { skt_id } => {
            let skt_info = link.skt_info(skt_id).await??;
            println!("{skt_info}")
        }
        ControlCommand::SendMsg {
            skt_id: socket_id,
            dest: destination,
            msg: message,
        } => {
            link.send_message(SendMessageArgs {
                socket_id,
                destination,
                content: Bytes::copy_from_slice(message.as_bytes()),
            })
            .await??;
        }
        ControlCommand::RecvMsg { skt_id: socket_id } => {
            match link.recv_message(socket_id.clone()).await? {
                Ok((msg, src)) => println!("{:?} from {}", msg, src),
                Err(e) => println!("error receiving message: {e}"),
            }
        }
        ControlCommand::GlobalRpc {
            id,
            dest: destination,
            method,
            args,
        } => {
            let args: Result<Vec<serde_json::Value>, _> =
                args.into_iter().map(|a| serde_yaml::from_str(&a)).collect();
            let args = args.context("arguments not YAML")?;
            let res = link
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
                OnionPublic::from_str(&onion_pk)?,
                rendezvous_fingerprint,
            );
            link.insert_rendezvous(locator).await??;
        }
        ControlCommand::GetRendezvous { key } => {
            let locator = link.get_rendezvous(key).await??;
            if let Some(locator) = locator {
                println!("{:?}", locator);
            } else {
                println!("No haven locator found for fingerprint {key}")
            }
        }
        ControlCommand::RendezvousHavenTest => {
            let mut fingerprint_bytes = [0; 32];
            rand::thread_rng().fill_bytes(&mut fingerprint_bytes);
            let fingerprint = RelayFingerprint::from_bytes(&fingerprint_bytes);
            let id_sk = HavenIdentitySecret::generate();
            let id_pk = id_sk.public();
            let locator = HavenLocator::new(id_sk, OnionSecret::generate().public(), fingerprint);
            eprintln!("created haven locator: {:?}", &locator);

            link.insert_rendezvous(locator.clone()).await??;
            eprintln!("inserted haven locator... sleeping for 5s");

            if let Some(fetched_locator) = link.get_rendezvous(id_pk.fingerprint()).await?? {
                eprintln!("got haven locator: {:?}", &fetched_locator);
                assert_eq!(locator.rendezvous_point, fetched_locator.rendezvous_point);
            } else {
                eprintln!("oh no couldn't find locator");
            }
        }
        ControlCommand::GraphDump { human } => {
            let res = link.graph_dump(human).await?;
            println!("{res}");
        }
        ControlCommand::MyRoutes => {
            let routes = link.my_routes().await?;
            println!("{}", serde_yaml::to_string(&routes)?);
        }
        ControlCommand::HavensInfo => {
            for info in link.havens_info().await? {
                println!("{} - {}", info.0, info.1);
            }
        }
        ControlCommand::ListDebts => {
            for debt in link.list_debts().await? {
                println!("{:?}", debt);
            }
        }
        ControlCommand::ListSettlements => {
            for settlement in link.list_settlements().await? {
                println!("{:?}", settlement);
            }
        }
        ControlCommand::Chat { chat_command } => match chat_command {
            ChatCommand::List => {
                let res = link.list_chats().await?;
                println!("{res}");
            }
            ChatCommand::Start { prefix } => {
                let clients = link.list_clients().await?;
                let relays = link.list_relays().await?;
                let client = client_by_prefix(clients, &prefix)?;
                let relay = relay_by_prefix(relays, &prefix)?;

                if client.is_some() && relay.is_none() {
                    let mut displayed: HashSet<(bool, String, SystemTime)> = HashSet::new();
                    let link = Arc::new(link);
                    let link_clone = link.clone();

                    let _listen_loop = smolscale::spawn(async move {
                        loop {
                            let msgs = if let Ok(msgs) = link.get_client_chat(client.unwrap()).await
                            {
                                msgs
                            } else {
                                println!("error fetching messages");
                                Timer::after(Duration::from_secs(1)).await;
                                continue;
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
                            match link_clone.send_client_chat_msg(client.unwrap(), msg).await {
                                Ok(_) => continue,
                                Err(e) => println!("ERROR: {e}"),
                            }
                        }
                    }
                } else if client.is_none() && relay.is_some() {
                    let mut displayed: HashSet<(bool, String, SystemTime)> = HashSet::new();
                    let link = Arc::new(link);
                    let link_clone = link.clone();

                    let _listen_loop = smolscale::spawn(async move {
                        loop {
                            let msgs = if let Ok(msgs) = link.get_relay_chat(relay.unwrap()).await {
                                msgs
                            } else {
                                println!("error fetching messages");
                                Timer::after(Duration::from_secs(1)).await;
                                continue;
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
                            match link_clone.send_relay_chat_msg(relay.unwrap(), msg).await {
                                Ok(_) => continue,
                                Err(e) => println!("ERROR: {e}"),
                            }
                        }
                    }
                } else if client.is_none() && relay.is_none() {
                    anyhow::bail!("no neighbor with this prefix")
                } else {
                    anyhow::bail!("more than one neighbor with this prefix")
                }
            }
            ChatCommand::GetClient { neighbor } => {
                let entries = link.get_client_chat(neighbor).await?;
                for (is_mine, text, time) in entries {
                    println!("{}", pretty_entry(is_mine, text, time));
                }
            }
            ChatCommand::GetRelay { neighbor } => {
                let entries = link.get_relay_chat(neighbor).await?;
                for (is_mine, text, time) in entries {
                    println!("{}", pretty_entry(is_mine, text, time));
                }
            }
            ChatCommand::SendClient { dest, msg } => link.send_client_chat_msg(dest, msg).await??,
            ChatCommand::SendRelay { dest, msg } => link.send_relay_chat_msg(dest, msg).await??,
        },
        ControlCommand::BindN2rRelay { skt_id: _, dock: _ } => todo!(),
        ControlCommand::BindN2rClient { skt_id: _, dock: _ } => todo!(),
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

fn client_by_prefix(clients: Vec<ClientId>, prefix: &str) -> anyhow::Result<Option<ClientId>> {
    let valid: Vec<ClientId> = clients
        .into_iter()
        .filter(|fp| fp.to_string().starts_with(prefix))
        .collect();
    if valid.len() == 1 {
        Ok(Some(valid[0]))
    } else if valid.is_empty() {
        Ok(None)
    } else {
        anyhow::bail!("Multiple clients have this prefix! Try a longer prefix.")
    }
}

fn relay_by_prefix(
    relays: Vec<RelayFingerprint>,
    prefix: &str,
) -> anyhow::Result<Option<RelayFingerprint>> {
    let valid: Vec<RelayFingerprint> = relays
        .into_iter()
        .filter(|fp| fp.to_string().starts_with(prefix))
        .collect();
    if valid.len() == 1 {
        Ok(Some(valid[0]))
    } else if valid.is_empty() {
        Ok(None)
    } else {
        anyhow::bail!("Multiple relays have this prefix! Try a longer prefix.")
    }
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
    async fn bind_n2r(&self, socket_id: String, anon_id: Option<String>, dock: Option<Dock>);

    async fn bind_haven(
        &self,
        socket_id: String,
        anon_id: Option<String>,
        dock: Option<Dock>,
        rendezvous_point: Option<RelayFingerprint>,
    );

    async fn skt_info(&self, skt_id: String) -> Result<RelayEndpoint, ControlProtErr>;

    async fn havens_info(&self) -> Vec<(String, String)>;

    async fn send_message(&self, args: SendMessageArgs) -> Result<(), ControlProtErr>;

    async fn recv_message(
        &self,
        socket_id: String,
    ) -> Result<(Bytes, RelayEndpoint), ControlProtErr>;

    async fn send_global_rpc(
        &self,
        args: GlobalRpcArgs,
    ) -> Result<serde_json::Value, GlobalRpcError>;

    async fn graph_dump(&self, human: bool) -> String;

    async fn my_routes(&self) -> serde_json::Value;

    async fn insert_rendezvous(&self, locator: HavenLocator) -> Result<(), DhtError>;

    async fn get_rendezvous(
        &self,
        fingerprint: HavenFingerprint,
    ) -> Result<Option<HavenLocator>, DhtError>;

    async fn list_clients(&self) -> Vec<ClientId>;

    async fn list_relays(&self) -> Vec<RelayFingerprint>;

    async fn list_chats(&self) -> String;

    async fn get_client_chat(&self, neigh: ClientId) -> Vec<(bool, String, SystemTime)>;

    async fn get_relay_chat(&self, neigh: RelayFingerprint) -> Vec<(bool, String, SystemTime)>;

    async fn send_client_chat_msg(&self, dest: ClientId, msg: String) -> Result<(), ChatError>;

    async fn send_relay_chat_msg(
        &self,
        dest: RelayFingerprint,
        msg: String,
    ) -> Result<(), ChatError>;

    async fn list_debts(&self) -> Vec<String>;

    async fn list_settlements(&self) -> Vec<String>;
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
#[derive(Serialize, Deserialize)]
pub struct SendMessageArgs {
    pub socket_id: String,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub destination: RelayEndpoint,
    #[serde_as(as = "serde_with::base64::Base64")]
    pub content: Bytes,
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
    #[error("error sending chat message {0}")]
    Send(String),
}
