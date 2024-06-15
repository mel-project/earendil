use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use bip39::Mnemonic;
use bytes::Bytes;
use clap::Parser;
use clap::Subcommand;
use earendil::config::ConfigFile;
use earendil::config::InRouteConfig;
use earendil::config::ObfsConfig;
use earendil::config::OutRouteConfig;
use earendil::ChatEntry;
use earendil::DebtEntry;
use earendil::IncomingMsg;
use earendil::LinkConfig;
use earendil::LinkNode;
use earendil::LinkStore;
use earendil::Node;
use earendil_crypt::AnonEndpoint;
use earendil_crypt::ClientId;
use earendil_crypt::RelayIdentitySecret;
use earendil_packet::InnerPacket;
use earendil_packet::Message;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

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
    // Control {
    //     #[arg(short, long, default_value = "127.0.0.1:18964")]
    //     connect: SocketAddr,
    //     #[command(subcommand)]
    //     control_command: ControlCommand,
    // },
    GenerateSeed,
}

pub fn init_tracing() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().compact())
        .with(
            EnvFilter::builder()
                .with_default_directive("earendil=debug".parse()?)
                .from_env_lossy(),
        )
        .init();
    Ok(())
}

#[tracing::instrument]
fn main() -> anyhow::Result<()> {
    // initialize tracing subscriber that displays to output
    init_tracing();

    match Args::parse().command {
        Commands::Daemon { config } => {
            let json: serde_json::Value =
                serde_yaml::from_slice(&std::fs::read(config).context("cannot read config file")?)
                    .context("syntax error in config file")?;
            let config_parsed: ConfigFile = serde_json::from_value(json)?;
            tracing::debug!(
                "parsed config file: {}",
                serde_json::to_string_pretty(&config_parsed)?
            );
            tracing::info!("about to init daemon!");
            let node = Node::new(config_parsed)?;
            match smol::future::block_on(node.wait_until_dead()) {
                Ok(_) => anyhow::bail!("daemon is dead, with no error msg"),
                Err(err) => anyhow::bail!(err),
            }
        }
        Commands::GenerateSeed => {
            let seed_phrase = gen_seed()?;
            println!("{}", seed_phrase);
            Ok(())
        }
    }
}

fn gen_seed() -> anyhow::Result<String> {
    let entropy: [u8; 16] = rand::random();
    let mnemonic = Mnemonic::from_entropy(&entropy)?;
    Ok(mnemonic.to_string().replace(' ', "-"))
}
