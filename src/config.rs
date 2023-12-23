use std::{collections::BTreeMap, io::Write, net::SocketAddr, path::PathBuf};

use anyhow::Context;
use earendil_crypt::{Fingerprint, IdentitySecret};
use earendil_packet::Dock;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::fs::OpenOptions;

use crate::socket::Endpoint;

/// A YAML-serializable configuration file
#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigFile {
    /// Seed of the long-term identity. Must be long and difficult to guess!
    ///
    /// If this is not provided, then we default to randomly creating an identity.
    #[serde(flatten)]
    pub identity: Option<Identity>,

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
        link_price: LinkPrice,
    },
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub enum OutRouteConfig {
    Obfsudp {
        #[serde_as(as = "serde_with::DisplayFromStr")]
        fingerprint: Fingerprint,
        #[serde_as(as = "serde_with::DisplayFromStr")]
        connect: SocketAddr,
        #[serde_as(as = "serde_with::hex::Hex")]
        cookie: [u8; 32],
        link_price: LinkPrice,
    },
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct UdpForwardConfig {
    pub listen: SocketAddr,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub remote: Endpoint,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct TcpForwardConfig {
    pub listen: SocketAddr,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub remote: Endpoint,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Socks5 {
    pub listen: SocketAddr,
    pub fallback: Fallback,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum Fallback {
    Block,
    PassThrough,
    SimpleProxy {
        #[serde_as(as = "serde_with::DisplayFromStr")]
        remote: Endpoint,
    },
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct HavenForwardConfig {
    #[serde(flatten)]
    pub identity: Identity,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub rendezvous: Fingerprint,
    pub handler: ForwardHandler,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ForwardHandler {
    UdpService {
        listen_dock: Dock,
        upstream: SocketAddr,
    },
    TcpService {
        listen_dock: Dock,
        upstream: SocketAddr,
    },
    SimpleProxy {
        listen_dock: Dock,
    },
}

#[derive(Serialize, Deserialize, Clone)]
/// A configuration for an identity, specified either as a human-readable seed that will be passed through a KDF, or a file that stores the raw binary bytes of the identity secret.
#[serde(rename_all = "snake_case")]
pub enum Identity {
    IdentitySeed(String),
    IdentityFile(PathBuf),
}

impl Identity {
    /// Actualizes this into an actual identity.
    pub fn actualize(&self) -> anyhow::Result<IdentitySecret> {
        match self {
            Identity::IdentitySeed(seed) => {
                log::warn!("initializing an identity from a fixed seed. this exposes secrets in the config file and is not recommended in production!");
                Ok(IdentitySecret::from_seed(seed))
            }
            Identity::IdentityFile(file) => {
                loop {
                    let bts = std::fs::read(file);
                    if let Ok(bts) = bts {
                        let bts: [u8; 32] = (&bts[..])
                            .try_into()
                            .context("identity file not of the right length")?;
                        return Ok(IdentitySecret::from_bytes(&bts));
                    } else {
                        log::info!("identity file {:?} does not exist yet, so creating", file);
                        // create it here
                        let identity = IdentitySecret::generate();
                        let mut options = OpenOptions::new();
                        options.create(true).write(true);

                        #[cfg(unix)]
                        {
                            use std::os::unix::prelude::OpenOptionsExt;
                            options.mode(0o600);
                        }

                        let mut file = options.open(file)?;
                        file.write_all(identity.as_bytes())?;
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct LinkPrice {
    /// in micromels
    pub max_outgoing_price: u64,
    pub incoming_price: u64,
    pub incoming_debt_limit: u64,
}
