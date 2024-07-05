use anyhow::Context;
use chrono::{DateTime, NaiveDateTime};
use colored::{ColoredString, Colorize};
use earendil_crypt::HavenIdentitySecret;
use earendil_packet::crypt::DhPublic;
use nanorpc_http::client::HttpRpcTransport;
use smol::Timer;
use std::{
    collections::HashSet, io::Write, net::SocketAddr, str::FromStr, sync::Arc, time::Duration,
};

use crate::{
    commands::{ChatCommand, ControlCommand},
    control_protocol::{ControlClient, GlobalRpcArgs},
    v2h_node::HavenLocator,
    ChatEntry,
};

pub async fn main_control(
    control_command: ControlCommand,
    connect: SocketAddr,
) -> anyhow::Result<()> {
    let control = ControlClient::from(HttpRpcTransport::new_with_proxy(
        connect.to_string(),
        nanorpc_http::client::Proxy::Direct,
    ));
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
            control.insert_rendezvous(locator).await?;
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
                let chats = control.list_chats().await??;
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
                        (entry.text, format_timestamp(entry.timestamp))
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
                let mut displayed: HashSet<ChatEntry> = HashSet::new();
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
                        for msg in msgs {
                            if !displayed.contains(&msg) {
                                println!("{}", pretty_entry(&msg));
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
                for entry in entries {
                    println!("{}", pretty_entry(&entry));
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

fn pretty_entry(entry: &ChatEntry) -> String {
    let date_time = DateTime::from_timestamp(entry.timestamp, 0)
        .unwrap()
        .naive_local();
    let arrow = if entry.is_outgoing {
        right_arrow()
    } else {
        left_arrow()
    };

    format!("{} {} {}", arrow, entry.text, pretty_time(date_time))
}

fn pretty_time(date_time: NaiveDateTime) -> ColoredString {
    format!("[{}]", date_time.format("%Y-%m-%d %H:%M:%S")).bright_yellow()
}

fn format_timestamp(timestamp: i64) -> String {
    let date_time = DateTime::from_timestamp(timestamp, 0)
        .unwrap()
        .naive_local();
    format!("[{}]", date_time.format("%Y-%m-%d %H:%M:%S"))
}
