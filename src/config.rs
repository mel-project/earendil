use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf};

use earendil_packet::Fingerprint;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// A YAML-serializable configuration file
#[derive(Serialize, Deserialize)]
pub struct ConfigFile {
    /// Path to the long-term identity.
    pub identity: PathBuf,
    /// Path to the state cache.
    pub state_cache: PathBuf,

    /// List of all listeners for incoming connections
    #[serde(default)]
    pub in_routes: BTreeMap<String, InRouteConfig>,
    /// List of all outgoing connections
    #[serde(default)]
    pub out_routes: BTreeMap<String, OutRouteConfig>,
}

#[serde_as]
#[derive(Serialize, Deserialize)]
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
