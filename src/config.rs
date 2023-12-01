use std::{collections::BTreeMap, net::SocketAddr};

use earendil_crypt::Fingerprint;
use earendil_packet::Dock;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::socket::Endpoint;

/// A YAML-serializable configuration file
#[derive(Serialize, Deserialize)]
pub struct ConfigFile {
    /// Seed of the long-term identity. Must be long and difficult to guess!
    ///
    /// If this is not provided, then we default to randomly creating an identity.
    pub identity_seed: Option<String>,

    /// Where to listen for the local control protocol.
    #[serde(default = "default_control_listen")]
    pub control_listen: SocketAddr,

    /// List of all listeners for incoming connections
    #[serde(default)]
    pub in_routes: BTreeMap<String, InRouteConfig>,
    /// List of all outgoing connections
    #[serde(default)]
    pub out_routes: BTreeMap<String, OutRouteConfig>,
    /// List of all client configs for udp forwarding
    #[serde(default)]
    pub udp_forwards: Vec<UdpForwardConfig>,
    /// List of all client configs for tcp forwarding
    #[serde(default)]
    pub tcp_forwards: Vec<TcpForwardConfig>,
    /// where and how to start a socks5 proxy
    pub socks5: Option<Socks5>,
    /// List of all haven configs
    #[serde(default)]
    pub havens: Vec<HavenForwardConfig>,
}

fn default_control_listen() -> SocketAddr {
    "127.0.0.1:18964".parse().unwrap()
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub enum InRouteConfig {
    Obfsudp {
        #[serde_as(as = "serde_with::DisplayFromStr")]
        listen: SocketAddr,
        secret: String,
    },
}

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case")]
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
#[serde(rename_all = "snake_case")]
pub struct UdpForwardConfig {
    pub forward_to: u16,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub remote_ep: Endpoint,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct TcpForwardConfig {
    pub forward_to: u16,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub remote_ep: Endpoint,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Socks5 {
    pub port: u16,
    pub fallback: Fallback,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Fallback {
    Block,
    PassThrough,
    SimpleProxy {
        #[serde_as(as = "serde_with::DisplayFromStr")]
        remote_ep: Endpoint,
    },
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct HavenForwardConfig {
    pub identity_seed: String,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub rendezvous: Fingerprint,
    pub handler: ForwardHandler,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ForwardHandler {
    UdpForward { from_dock: Dock, to_port: u16 },
    TcpForward { from_dock: Dock, to_port: u16 },
    SimpleProxy { listen_dock: Dock },
}
