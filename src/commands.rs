use std::{net::SocketAddr, path::PathBuf};

use clap::{Subcommand, arg};
use earendil_crypt::{HavenFingerprint, RelayFingerprint};

#[derive(Subcommand)]
pub enum Commands {
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
        control_command: ControlCommand,
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

#[derive(Subcommand)]
pub enum ControlCommand {
    /// Prints the information of all hosted havens
    HavensInfo,

    /// Send a GlobalRpc request to a destination.
    GlobalRpc {
        #[arg(long)]
        id: Option<String>,
        #[arg(short, long)]
        dest: RelayFingerprint,
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
        rendezvous_fingerprint: RelayFingerprint,
    },

    /// Looks up a rendezvous haven locator.
    GetRendezvous {
        #[arg(short, long)]
        key: HavenFingerprint,
    },

    /// Dumps the relay graph in graphviz format.
    RelayGraphviz,

    /// Dumps my own routes.
    MyRoutes,
}

#[derive(Subcommand)]
pub enum ChatCommand {
    /// print a summary of all your conversations
    List,

    /// start an interactive chat session with a neighbor
    Start {
        /// The fingerprint or client id of the neighbor to start a chat with.
        /// Accepts prefixes: TODO
        neighbor: String,
    },

    /// Pulls conversation between you and neighbor
    Get {
        #[arg(short, long)]
        src: String,
    },

    /// Sends a single chat message to a neighbor
    Send {
        #[arg(short, long)]
        dest: String,
        #[arg(short, long)]
        msg: String,
    },
}
