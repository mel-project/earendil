use std::{fmt::Display, num::ParseIntError, str::FromStr};

use bytes::Bytes;
use earendil_crypt::RelayFingerprint;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Identifies a specific node in the network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeAddr {
    pub relay: RelayFingerprint,
    pub client_id: u64,
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
