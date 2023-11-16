use anyhow::Context;
use clap::{Parser, Subcommand};
use commands::ControlCommands;
use config::ConfigFile;
use control_protocol::main_control;
use daemon::Daemon;
use std::{net::SocketAddr, path::PathBuf};

mod commands;
mod config;
pub mod control_protocol;
pub mod daemon;
mod havens;
mod sockets;
mod utils;

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

    /// Runs a control-protocol verb.
    Control {
        #[arg(short, long, default_value = "127.0.0.1:18964")]
        connect: SocketAddr,
        #[command(subcommand)]
        control_command: ControlCommands,
    },
}

fn main() -> anyhow::Result<()> {
    match Args::parse().command {
        Commands::Daemon { config } => {
            let config_parsed: ConfigFile =
                serde_yaml::from_slice(&std::fs::read(config).context("cannot read config file")?)
                    .context("syntax error in config file")?;

            let _daemon = Daemon::init(config_parsed)?;
            Ok(())
        }
        Commands::Control {
            control_command,
            connect,
        } => smolscale::block_on(main_control(control_command, connect)),
    }
}
