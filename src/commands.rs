use crate::socket::Endpoint;
use clap::{arg, Subcommand};
use earendil_crypt::Fingerprint;
use earendil_packet::Dock;

#[derive(Subcommand)]
pub enum ControlCommands {
    /// Binds to a N2rSocket.
    BindN2r {
        #[arg(long)]
        /// tag for this socket
        skt_id: String,
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
        skt_id: String,
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

    /// Prints the fingerprint and dock of a socket
    SktInfo {
        #[arg(long)]
        skt_id: String,
    },

    /// Prints the information of all hosted havens
    HavensInfo,

    /// Sends a message using a given socket to a destination.
    SendMsg {
        #[arg(long)]
        /// tag for the socket to use
        skt_id: String,
        #[arg(short, long)]
        /// destination fingerprint::dock
        dest: Endpoint,
        #[arg(short, long)]
        /// message
        msg: String,
    },

    /// Blocks until a message is received.
    RecvMsg {
        #[arg(long)]
        /// tag for the socket to listen to
        skt_id: String,
    },

    /// Send a GlobalRpc request to a destination.
    GlobalRpc {
        #[arg(long)]
        id: Option<String>,
        #[arg(short, long)]
        dest: Fingerprint,
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
    GraphDump {
        #[arg(short, long)]
        human: bool,
    },

    /// Dumps my own routes.
    MyRoutes,
}
