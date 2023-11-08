use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf};

use earendil_crypt::Fingerprint;
use earendil_packet::Dock;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::daemon::n2r_socket::Endpoint;

/// A YAML-serializable configuration file
#[derive(Serialize, Deserialize)]
pub struct ConfigFile {
    /// Path to the long-term identity.
    pub identity: PathBuf,
    /// Path to the state cache.
    pub state_cache: PathBuf,

    /// Where to listen for the local control protocol.
    #[serde(default = "default_control_listen")]
    pub control_listen: SocketAddr,

    /// List of all listeners for incoming connections
    #[serde(default)]
    pub in_routes: BTreeMap<String, InRouteConfig>,
    /// List of all outgoing connections
    #[serde(default)]
    pub out_routes: BTreeMap<String, OutRouteConfig>,

    pub udp_forwards: Vec<UdpForwardConfig>,

    pub havens: Vec<HavenForwardConfig>,
}

fn default_control_listen() -> SocketAddr {
    "127.0.0.1:18964".parse().unwrap()
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "protocol", rename_all = "kebab-case")]
pub enum InRouteConfig {
    Obfsudp {
        #[serde_as(as = "serde_with::DisplayFromStr")]
        listen: SocketAddr,
        secret: String,
    },
}

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "kebab-case")]
pub enum OutRouteConfig {
    Obfsudp {
        #[serde_as(as = "serde_with::DisplayFromStr")]
        fingerprint: Fingerprint,
        #[serde_as(as = "serde_with::DisplayFromStr")]
        connect: SocketAddr,
        #[serde_as(as = "serde_with::hex::Hex")]
        cookie: [u8; 32],
    },
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
pub struct UdpForwardConfig {
    pub forward_to: u16,
    pub remote_ep: Endpoint,
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct HavenForwardConfig {
    pub identity: PathBuf,
    pub handler: ForwardHandler,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
pub enum ForwardHandler {
    Udp { from_dock: Dock, to_port: u16 },
}
