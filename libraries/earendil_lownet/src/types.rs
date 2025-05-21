use std::net::SocketAddr;

use bytes::Bytes;
use earendil_crypt::{RelayFingerprint, RelayIdentitySecret};
use earendil_topology::NodeAddr;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// The identity of the node. Either a relay or a client.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeIdentity {
    Relay(RelayIdentitySecret),
    ClientBearer(u128),
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
