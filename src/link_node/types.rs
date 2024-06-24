use std::{collections::BTreeMap, fmt::Display, path::PathBuf, sync::Arc};

use bytes::Bytes;
use dashmap::DashMap;
use earendil_crypt::{AnonEndpoint, RelayFingerprint, RelayIdentitySecret};
use earendil_packet::{crypt::DhSecret, InnerPacket};
use earendil_topology::RelayGraph;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::{
    config::{InRouteConfig, OutRouteConfig},
    LinkStore,
};

use super::{
    link::Link,
    payment_system::{PaymentSystem, PaymentSystemSelector},
};

pub type ClientId = u64;

#[derive(Clone, Copy, Eq, PartialEq, Debug, Hash, Serialize, Deserialize)]
pub enum NodeId {
    Relay(RelayFingerprint),
    Client(ClientId),
}

impl Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let displayable = match self {
            NodeId::Relay(relay_id) => relay_id.to_string(),
            NodeId::Client(client_id) => client_id.to_string(),
        };
        write!(f, "{}", displayable)
    }
}

#[derive(Clone)]
pub enum NodeIdSecret {
    Relay(RelayIdentitySecret),
    Client(ClientId),
}

impl NodeIdSecret {
    pub fn public(&self) -> NodeId {
        match self {
            NodeIdSecret::Relay(relay_id) => NodeId::Relay(relay_id.public().fingerprint()),
            NodeIdSecret::Client(client_id) => NodeId::Client(*client_id),
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
    pub price: i64,
    pub debt_limit: i64,
    pub paysystem_name_addrs: Vec<(String, String)>,
}

pub struct LinkConfig {
    pub relay_config: Option<(RelayIdentitySecret, BTreeMap<String, InRouteConfig>)>,
    pub out_routes: BTreeMap<String, OutRouteConfig>,
    pub payment_systems: Vec<Box<dyn PaymentSystem>>,
    pub db_path: PathBuf,
}

#[derive(Clone)]
pub(super) struct LinkNodeCtx {
    pub cfg: Arc<LinkConfig>,
    pub my_id: NodeIdSecret,
    pub my_onion_sk: DhSecret,
    pub relay_graph: Arc<RwLock<RelayGraph>>,
    pub link_table: Arc<DashMap<NodeId, (Arc<Link>, LinkPaymentInfo)>>,
    pub payment_systems: Arc<PaymentSystemSelector>,
    pub store: Arc<LinkStore>,
    pub mel_client: Arc<melprot::Client>,
}
