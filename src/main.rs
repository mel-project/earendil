use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use config::ConfigFile;
use control_protocol::main_control;
use earendil_crypt::Fingerprint;

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
pub enum ControlCommands {
    /// Send a message to a destination.
    SendMessage {
        #[arg(short, long)]
        destination: Fingerprint,
        #[arg(short, long)]
        message: String,
    },

    /// Dumps the graph.
    GraphDump,
}

fn main() -> anyhow::Result<()> {
    match Args::parse().command {
        Commands::Daemon { config } => {
            let config: ConfigFile =
                serde_yaml::from_slice(&std::fs::read(config).context("cannot read config file")?)
                    .context("syntax error in config file")?;
            daemon::main_daemon(config)
        }
        Commands::Control { control_command } => smolscale::block_on(main_control(control_command)),
    }
}
