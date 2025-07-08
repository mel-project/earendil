use std::{net::SocketAddr, path::PathBuf};

use clap::Subcommand;

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
        /// Output raw JSON instead of pretty YAML
        #[arg(long)]
        json: bool,
        /// Method on the control protocol to invoke
        method: String,
        /// Arguments to the method, expressed as YAML values
        args: Vec<String>,
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
