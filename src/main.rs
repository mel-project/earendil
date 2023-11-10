use std::{net::SocketAddr, path::PathBuf};

use anyhow::Context;
use clap::{Parser, Subcommand};
use config::ConfigFile;
use control_protocol::main_control;
use daemon::n2r_socket::Endpoint;
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

    /// Runs a control-protocol verb.
    Control {
        #[arg(short, long, default_value = "127.0.0.1:18964")]
        connect: SocketAddr,
        #[command(subcommand)]
        control_command: ControlCommands,
    },
}

#[derive(Subcommand)]
pub enum ControlCommands {
    /// Binds to a N2rSocket.
    BindN2r {
        #[arg(long)]
        /// tag for this socket
        socket_id: String,
        #[arg(long)]
        /// tag for an anonymous fingerprint
        anon_id: Option<String>,
        #[arg(long)]
        /// specific dock to bind to
        dock: Option<Dock>,
    },

    /// Binds to a HavenSocket.
    BindHaven {
        #[arg(long)]
        /// tag for this socket
        socket_id: String,
        #[arg(long)]
        /// tag for an anonymous fingerprint
        anon_id: Option<String>,
        #[arg(long)]
        /// specific dock to bind to
        dock: Option<Dock>,
        #[arg(long)]
        /// fingerprint of rendezvous point. Specify this if you are the haven server.
        rendezvous: Option<Fingerprint>,
    },

    /// Sends a message using a given socket to a destination.
    SendMessage {
        #[arg(long)]
        /// tag for the socket to use
        socket_id: String,
        #[arg(short, long)]
        /// destination fingerprint::dock
        destination: Endpoint,
        #[arg(short, long)]
        /// message
        message: String,
    },

    /// Blocks until a message is received.
    RecvMessage {
        #[arg(long)]
        /// tag for the socket to listen to
        socket_id: String,
    },

    /// Send a GlobalRpc request to a destination.
    GlobalRpc {
        #[arg(long)]
        id: Option<String>,
        #[arg(short, long)]
        destination: Fingerprint,
        #[arg(short, long)]
        method: String,
        args: Vec<String>,
    },

    /// Insert a rendezvous haven locator into the dht.
    InsertRendezvous {
        #[arg(short, long)]
        identity_sk: String,
        #[arg(short, long)]
        onion_pk: String,
        #[arg(short, long)]
        rendezvous_fingerprint: Fingerprint,
    },

    /// Looks up a rendezvous haven locator.
    GetRendezvous {
        #[arg(short, long)]
        key: Fingerprint,
    },

    /// Insert and get a randomly generated HavenLocator.
    RendezvousHavenTest,

    /// Dumps the graph.
    GraphDump,

    /// Dumps my own routes.
    MyRoutes,
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
