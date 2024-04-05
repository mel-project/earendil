use std::{collections::BTreeMap, io::Write, net::SocketAddr, path::PathBuf};

use anyhow::Context;
use earendil_crypt::{HavenIdentitySecret, RelayFingerprint, RelayIdentitySecret};

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::fs::OpenOptions;
use tracing::instrument;

use crate::haven::HavenEndpoint;

/// A YAML-serializable configuration file
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    /// Seed of the long-term identity. Must be long and difficult to guess!
    ///
    /// If this is not provided, then we default to randomly creating an identity.
    #[serde(flatten)]
    pub identity: Option<Identity>,

    /// Path to database file.
    pub state_cache: Option<PathBuf>,

    /// Where to listen for the local control protocol.
    #[serde(default = "default_control_listen")]
    pub control_listen: SocketAddr,

    /// List of all listeners for incoming connections
    #[serde(default)]
    pub in_routes: BTreeMap<String, InRouteConfig>,
    /// List of all outgoing connections
    #[serde(default)]
    pub out_routes: BTreeMap<String, OutRouteConfig>,

    /// Contains the automatic settlement difficulty if accepted
    pub auto_settle: Option<AutoSettle>,

    /// List of all client configs for udp forwarding
    #[serde(default)]
    pub udp_forwards: Vec<UdpForwardConfig>,
    /// List of all client configs for tcp forwarding
    #[serde(default)]
    pub tcp_forwards: Vec<TcpForwardConfig>,
    /// where and how to start a socks5 proxy
    pub socks5: Option<Socks5Config>,
    /// List of all haven configs
    #[serde(default)]
    pub havens: Vec<HavenConfig>,
}

impl ConfigFile {
    pub fn is_client(&self) -> bool {
        self.identity.is_none()
    }
}

fn default_control_listen() -> SocketAddr {
    "127.0.0.1:18964".parse().unwrap()
}

#[derive(Serialize, Deserialize, Clone)]
pub struct InRouteConfig {
    pub listen: SocketAddr,
    pub obfs: ObfsConfig,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum ObfsConfig {
    None,
    Sosistab3(String),
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
pub struct OutRouteConfig {
    pub connect: String,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub fingerprint: RelayFingerprint,
    pub obfs: ObfsConfig,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct UdpForwardConfig {
    pub listen: SocketAddr,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub remote: HavenEndpoint,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct TcpForwardConfig {
    pub listen: SocketAddr,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub remote: HavenEndpoint,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub struct Socks5Config {
    pub listen: SocketAddr,
    pub fallback: Socks5Fallback,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Socks5Fallback {
    Block,
    PassThrough,
    SimpleProxy {
        #[serde_as(as = "serde_with::DisplayFromStr")]
        remote: HavenEndpoint,
    },
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct HavenConfig {
    #[serde(flatten)]
    pub identity: Identity,
    pub listen_port: u16,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub rendezvous: RelayFingerprint,
    pub handler: HavenHandler,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HavenHandler {
    TcpService { upstream: SocketAddr },
    SimpleProxy,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
/// A configuration for an identity, specified either as a human-readable seed that will be passed through a KDF, or a file that stores the raw binary bytes of the identity secret.
#[serde(rename_all = "snake_case")]
pub enum Identity {
    IdentitySeed(String),
    IdentityFile(PathBuf),
}

impl Identity {
    #[instrument(skip(self))]
    /// Actualizes this into an actual identity.
    pub fn actualize_relay(&self) -> anyhow::Result<RelayIdentitySecret> {
        match self {
            Identity::IdentitySeed(seed) => {
                tracing::warn!("initializing an identity from a fixed seed. this exposes secrets in the config file and is not recommended in production!");
                Ok(RelayIdentitySecret::from_seed(seed))
            }
            Identity::IdentityFile(file) => {
                loop {
                    let bts = std::fs::read(file);
                    if let Ok(bts) = bts {
                        let bts: [u8; 32] = (&bts[..])
                            .try_into()
                            .context("identity file not of the right length")?;
                        return Ok(RelayIdentitySecret::from_bytes(&bts));
                    } else {
                        tracing::info!("identity file {:?} does not exist yet, so creating", file);
                        // create it here
                        let identity = RelayIdentitySecret::generate();
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

    pub fn actualize_haven(&self) -> anyhow::Result<HavenIdentitySecret> {
        match self {
            Identity::IdentitySeed(seed) => {
                tracing::warn!("initializing an identity from a fixed seed. this exposes secrets in the config file and is not recommended in production!");
                Ok(HavenIdentitySecret::from_seed(seed))
            }
            Identity::IdentityFile(file) => {
                loop {
                    let bts = std::fs::read(file);
                    if let Ok(bts) = bts {
                        let bts: [u8; 32] = (&bts[..])
                            .try_into()
                            .context("identity file not of the right length")?;
                        return Ok(HavenIdentitySecret::from_bytes(&bts));
                    } else {
                        tracing::info!("identity file {:?} does not exist yet, so creating", file);
                        // create it here
                        let identity = HavenIdentitySecret::generate();
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

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default)]
pub struct LinkPrice {
    /// in micromel
    pub max_outgoing_price: u64,
    pub incoming_price: u64,
    pub incoming_debt_limit: u64,
}

#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct AutoSettle {
    /// number of seconds in between settlements
    pub interval: u64,
}
