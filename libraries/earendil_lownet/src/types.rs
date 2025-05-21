use std::{fmt::Display, net::SocketAddr, num::ParseIntError, str::FromStr};

use bytes::Bytes;
use earendil_crypt::{RelayFingerprint, RelayIdentitySecret};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use thiserror::Error;

/// The identity of the node. Either a relay or a client.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeIdentity {
    Relay(RelayIdentitySecret),
    ClientBearer(u128),
}

/// Identifies a specific node in the network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeAddr {
    pub relay: RelayFingerprint,
    pub client_id: u64,
}

impl NodeAddr {
    pub fn new(relay: RelayFingerprint, client_id: u64) -> Self {
        NodeAddr { relay, client_id }
    }
}

impl Display for NodeAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "na-{}-{}", self.relay, self.client_id)
    }
}

/// Errors that can occur when parsing a `NodeAddr` from a string.
#[derive(Debug, Error)]
pub enum NodeAddrParseError {
    #[error("invalid NodeAddr format, expected `na-<relay>-<client_id>`")]
    InvalidFormat,

    #[error("invalid relay fingerprint: {0}")]
    InvalidRelayFingerprint(#[source] <RelayFingerprint as FromStr>::Err),

    #[error("invalid client id: {0}")]
    InvalidClientId(ParseIntError),
}

impl FromStr for NodeAddr {
    type Err = NodeAddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(3, '-');
        if parts.next() != Some("na") {
            return Err(NodeAddrParseError::InvalidFormat);
        }

        let relay_str = parts.next().ok_or(NodeAddrParseError::InvalidFormat)?;
        let client_str = parts.next().ok_or(NodeAddrParseError::InvalidFormat)?;

        // Parse the relay fingerprint
        let relay = relay_str
            .parse()
            .map_err(NodeAddrParseError::InvalidRelayFingerprint)?;

        let client_id = client_str
            .parse()
            .map_err(NodeAddrParseError::InvalidClientId)?;

        Ok(NodeAddr { relay, client_id })
    }
}

/// A datagram traveling through the lownet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Datagram {
    pub ttl: u8,
    pub dest_addr: NodeAddr,
    pub payload: Bytes,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
/// Configuration for a dialer of outgoing links
pub struct OutLinkConfig {
    pub connect: String,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub fingerprint: RelayFingerprint,
    pub obfs: ObfsConfig,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
/// Configuration for a listener for incoming links
pub struct InLinkConfig {
    pub listen: SocketAddr,
    pub obfs: ObfsConfig,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
/// Configuration for obfuscation schemes.
pub enum ObfsConfig {
    None,
    Sosistab3(String),
}
