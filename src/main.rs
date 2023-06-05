use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use config::ConfigFile;

mod config;
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
}

fn main() -> anyhow::Result<()> {
    match Args::parse().command {
        Commands::Daemon { config } => {
            let config: ConfigFile =
                serde_yaml::from_slice(&std::fs::read(config).context("cannot read config file")?)
                    .context("syntax error in config file")?;
            daemon::main_daemon(config)
        }
    }
}
