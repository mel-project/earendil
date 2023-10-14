use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf};

use earendil_crypt::Fingerprint;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

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
