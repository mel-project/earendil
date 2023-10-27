use std::{net::SocketAddr, path::PathBuf};

use anyhow::Context;
use clap::{Parser, Subcommand};
use config::ConfigFile;
use control_protocol::main_control;
use earendil_crypt::Fingerprint;
use earendil_packet::Dock;

mod config;
pub mod control_protocol;
pub mod daemon;

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
        #[arg(short, long, default_value = "127.0.0.1:18964")]
        connect: SocketAddr,
        #[command(subcommand)]
        control_command: ControlCommands,
    },
}

#[derive(Subcommand)]
pub enum ControlCommands {
    /// Send a message to a destination.
    SendMessage {
        #[arg(long)]
        id: Option<String>,
        source_dock: Dock,
        dest_dock: Dock,
        #[arg(short, long)]
        destination: Fingerprint,
        #[arg(short, long)]
        message: String,
    },

    /// Send a GlobalRpc request to a destination
    SendGlobalRpc {
        #[arg(long)]
        id: Option<String>,
        source_dock: Option<Dock>,
        #[arg(short, long)]
        destination: Fingerprint,
        #[arg(short, long)]
        method: String,
        args: Vec<String>,
    },

    /// Dumps the graph.
    GraphDump,

    /// Dumps my own routes
    MyRoutes,

    /// Blocks until a message is received.
    RecvMessage,
}

fn main() -> anyhow::Result<()> {
    match Args::parse().command {
        Commands::Daemon { config } => {
            let config_parsed: ConfigFile =
                serde_yaml::from_slice(&std::fs::read(config).context("cannot read config file")?)
                    .context("syntax error in config file")?;

            daemon::main_daemon(config_parsed)
        }
        Commands::Control {
            control_command,
            connect,
        } => smolscale::block_on(main_control(control_command, connect)),
    }
}
