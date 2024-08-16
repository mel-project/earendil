use std::{collections::BTreeMap, fmt, io::Write, net::SocketAddr, path::PathBuf};

use anyhow::Context;
use bip39::Mnemonic;
use earendil_crypt::{HavenEndpoint, HavenIdentitySecret, RelayFingerprint, RelayIdentitySecret};
use earendil_packet::PrivacyConfig;
use earendil_topology::ExitConfig;
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::serde_as;
use std::fs::OpenOptions;
use tracing::instrument;

/// A YAML-serializable configuration file
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    pub relay_config: Option<RelayConfig>,

    /// Path to database file.
    pub db_path: Option<PathBuf>,

    /// Where to listen for the local control protocol.
    #[serde(default = "default_control_listen")]
    pub control_listen: SocketAddr,

    /// List of all outgoing connections
    #[serde(default)]
    pub out_routes: BTreeMap<String, OutRouteConfig>,

    #[serde(default)]
    pub payment_methods: Vec<PaymentSystemKind>,

    /// List of all client configs for udp forwarding
    #[serde(default)]
    pub udp_forwards: Vec<UdpForwardConfig>,
    /// List of all client configs for tcp forwarding
    #[serde(default)]
    pub tcp_forwards: Vec<TcpForwardConfig>,
    /// where and how to start a socks5 proxy
    #[serde(default = "default_socks5")]
    pub socks5: Socks5Config,
    /// List of all haven configs
    #[serde(default)]
    pub havens: Vec<HavenConfig>,

    /// the haven address for our melprot::Client to bootstrap on
    /// e.g. http://<haven_addr>.haven:<port>
    pub mel_bootstrap: Option<String>,

    /// Configuration for relay nodes to host an exit.
    pub exit_config: Option<ExitConfig>,

    /// Configuration for mixnet privacy parameters.
    #[serde(default)]
    pub privacy_config: PrivacyConfig,
}

impl ConfigFile {
    pub fn is_client(&self) -> bool {
        self.relay_config.is_none()
    }
}

fn default_control_listen() -> SocketAddr {
    "127.0.0.1:18964".parse().unwrap()
}

fn default_socks5() -> Socks5Config {
    Socks5Config {
        listen: "127.0.0.1:30003".parse().unwrap(),
        fallback: Socks5Fallback::SimpleProxy { exit_nodes: vec![] },
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RelayConfig {
    /// Seed of the long-term identity. Must be long and difficult to guess!
    #[serde(flatten)]
    pub identity: Identity,

    /// List of all listeners for incoming connections
    #[serde(default)]
    pub in_routes: BTreeMap<String, InRouteConfig>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InRouteConfig {
    pub listen: SocketAddr,
    pub obfs: ObfsConfig,
    pub price_config: PriceConfig,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ObfsConfig {
    None,
    Sosistab3(String),
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OutRouteConfig {
    pub connect: String,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub fingerprint: RelayFingerprint,
    pub obfs: ObfsConfig,
    pub price_config: PriceConfig,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PriceConfig {
    #[serde(deserialize_with = "deserialize_nonneg_f64")]
    /// price, in micromel. Must be nonnegative
    pub inbound_price: f64,
    /// debt limit, in micromel
    pub inbound_debt_limit: f64,
    /// max accepted price, in micromel
    pub outbound_max_price: f64,
    /// min accepted debt limit, in micromel = how much you're willing to pre-pay
    pub outbound_min_debt_limit: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum AcceptPaymentMethod {
    Dummy,
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
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Socks5Config {
    pub listen: SocketAddr,
    pub fallback: Socks5Fallback,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Socks5Fallback {
    Block,
    PassThrough,
    SimpleProxy {
        #[serde_as(as = "Vec<serde_with::DisplayFromStr>")]
        exit_nodes: Vec<RelayFingerprint>,
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

impl HavenConfig {
    pub fn new_for_exit(my_relay_fp: RelayFingerprint) -> anyhow::Result<Self> {
        let identity_seed = Self::generate_identity_seed()?;
        let listen_port = Self::generate_random_local_port();
        let rendezvous = my_relay_fp;

        Ok(HavenConfig {
            identity: Identity::IdentitySeed(identity_seed),
            listen_port,
            rendezvous,
            handler: HavenHandler::Exit,
        })
    }

    /// Generates a human-readable identity seed using bip39.
    fn generate_identity_seed() -> anyhow::Result<String> {
        let entropy: [u8; 16] = rand::random();
        let mnemonic = Mnemonic::from_entropy(&entropy)?;
        Ok(mnemonic.to_string().replace(' ', "-"))
    }

    /// Generates a random local port number within the typical non-reserved range.
    /// NOTE: if this turns out to cause issues, we can choose a different range.
    fn generate_random_local_port() -> u16 {
        rand::thread_rng().gen_range(1024..65535)
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HavenHandler {
    TcpService { upstream: SocketAddr },
    Exit,
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

fn deserialize_nonneg_f64<'de, D>(deserializer: D) -> Result<f64, D::Error>
where
    D: Deserializer<'de>,
{
    struct NonNegativeF64Visitor;

    impl<'de> serde::de::Visitor<'de> for NonNegativeF64Visitor {
        type Value = f64;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a non-negative f64")
        }

        fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if value >= 0.0 {
                Ok(value)
            } else {
                Err(E::custom(format!(
                    "f64 must be non-negative, got {}",
                    value
                )))
            }
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(value as f64)
        }
    }

    deserializer.deserialize_any(NonNegativeF64Visitor)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PaymentSystemKind {
    Dummy,
    Pow,
    OnChain(String),
    // Astrape,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SupportedPaymentSystems {
    pub dummy: Option<()>,
    pub pow: Option<()>,
    pub on_chain: Option<OnChain>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OnChain {
    pub secret: String,
}

impl SupportedPaymentSystems {
    pub fn get_available(&self) -> anyhow::Result<Vec<PaymentSystemKind>> {
        let mut available = vec![];
        if self.dummy.is_some() {
            available.push(PaymentSystemKind::Dummy);
        }
        if self.pow.is_some() {
            available.push(PaymentSystemKind::Pow);
        }
        if let Some(OnChain { secret }) = &self.on_chain {
            available.push(PaymentSystemKind::OnChain(secret.to_string()))
        }
        Ok(available)
    }
}
