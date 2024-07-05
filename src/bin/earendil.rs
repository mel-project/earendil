use anyhow::Context;
use bip39::Mnemonic;
use clap::Parser;
use earendil::config::ConfigFile;
use earendil::main_control;
use earendil::Commands;
use earendil::Node;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

/// Official implementation of an Earendil node
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
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
    init_tracing().unwrap();

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

            let node = smol::block_on(async move {
                let node = Node::start(config_parsed).await?;
                anyhow::Ok(node)
            })?;

            smol::future::block_on(async {
                match node.wait_until_dead().await {
                    Ok(_) => anyhow::bail!("daemon is dead, with no error msg"),
                    Err(err) => anyhow::bail!(err),
                }
            })
        }
        Commands::Control {
            connect,
            control_command,
        } => smolscale::block_on(main_control(control_command, connect)),
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
