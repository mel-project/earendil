use std::{collections::BTreeMap, fmt::Display, path::PathBuf};

use bytes::Bytes;
use earendil_crypt::{AnonEndpoint, RelayFingerprint, RelayIdentitySecret};
use earendil_packet::{InnerPacket, PrivacyConfig};
use earendil_topology::ExitInfo;
use serde::{Deserialize, Serialize};

use crate::{
    config::{InRouteConfig, OutRouteConfig},
};

use super::payment_system::PaymentSystem;

pub type ClientId = u64;

#[derive(Clone, Copy, Eq, PartialEq, Debug, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NeighborId {
    Relay(RelayFingerprint),
    Client(ClientId),
}

impl Display for NeighborId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let displayable = match self {
            NeighborId::Relay(relay_id) => relay_id.to_string(),
            NeighborId::Client(client_id) => client_id.to_string(),
        };
        write!(f, "{}", displayable)
    }
}

#[derive(Clone)]
pub enum NeighborIdSecret {
    Relay(RelayIdentitySecret),
    Client(ClientId),
}

impl NeighborIdSecret {
    pub fn public(&self) -> NeighborId {
        match self {
            NeighborIdSecret::Relay(relay_id) => NeighborId::Relay(relay_id.public().fingerprint()),
            NeighborIdSecret::Client(client_id) => NeighborId::Client(*client_id),
        }
    }
}

/// Incoming messages from the link layer that are addressed to "us".
#[derive(Debug)]
pub enum IncomingMsg {
    Forward {
        from: AnonEndpoint,
        body: InnerPacket,
    },
    Backward {
        rb_id: u64,
        body: Bytes,
    },
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct LinkPaymentInfo {
    pub price: f64,
    pub debt_limit: f64,
    pub paysystem_name_addrs: Vec<(String, String)>,
}

pub struct LinkConfig {
    pub relay_config: Option<(RelayIdentitySecret, BTreeMap<String, InRouteConfig>)>,
    pub out_routes: BTreeMap<String, OutRouteConfig>,
    pub payment_systems: Vec<Box<dyn PaymentSystem>>,
    pub db_path: PathBuf,
    pub exit_info: Option<ExitInfo>,
    pub privacy_config: PrivacyConfig,
}
