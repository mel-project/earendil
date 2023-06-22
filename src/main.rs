use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use config::ConfigFile;
use control_protocol::{ControlClient, SendMessageArgs};
use earendil_packet::Fingerprint;
use nanorpc_http::client::HttpRpcTransport;

mod config;
pub mod control_protocol;
mod daemon;

/// Official implementation of an Earendil node
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Runs an Earendil daemon.
    Daemon {
        #[arg(short, long)]
        config: PathBuf,
    },

    /// Runs a control-protocol verb
    Control {
        #[command(subcommand)]
        control_command: ControlCommands,
    },
}

#[derive(Subcommand)]
enum ControlCommands {
    /// Send a message to a destination.
    SendMessage {
        #[arg(short, long)]
        destination: Fingerprint,
        #[arg(short, long)]
        message: String,
    },
}

fn main() -> anyhow::Result<()> {
    match Args::parse().command {
        Commands::Daemon { config } => {
            let config: ConfigFile =
                serde_yaml::from_slice(&std::fs::read(config).context("cannot read config file")?)
                    .context("syntax error in config file")?;
            daemon::main_daemon(config)
        }
        Commands::Control { control_command } => smolscale::block_on(async move {
            let conn =
                ControlClient::from(HttpRpcTransport::new("127.0.0.1:18964".parse().unwrap()));
            match control_command {
                ControlCommands::SendMessage {
                    destination,
                    message,
                } => {
                    conn.send_message(SendMessageArgs {
                        destination,
                        content: [0; 8192],
                    })
                    .await??;
                }
            }
            Ok(())
        }),
    }
}
