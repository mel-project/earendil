use anyhow::Context;
use clap::{Parser, Subcommand};
use earendil::commands::ControlCommands;
use earendil::config::ConfigFile;
use earendil::control_protocol::main_control;
use earendil::daemon::Daemon;
use std::{net::SocketAddr, path::PathBuf};

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
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("earendil=trace"))
        .init();

    match Args::parse().command {
        Commands::Daemon { config } => {
            let json: serde_json::Value =
                serde_yaml::from_slice(&std::fs::read(config).context("cannot read config file")?)
                    .context("syntax error in config file")?;
            let config_parsed: ConfigFile = serde_json::from_value(json)?;
            log::info!("about to init daemon!");
            let _daemon = Daemon::init(config_parsed)?;
            loop {
                std::thread::park()
            }
        }
        Commands::Control {
            control_command,
            connect,
        } => smolscale::block_on(main_control(control_command, connect)),
    }
}
