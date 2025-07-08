use std::{collections::BTreeMap, path::PathBuf};

use bytes::Bytes;
use earendil_crypt::{AnonEndpoint, RelayIdentitySecret};
use earendil_packet::{InnerPacket, PrivacyConfig};
use earendil_topology::ExitInfo;

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

pub struct LinkConfig {
    pub relay_config: Option<(
        RelayIdentitySecret,
        BTreeMap<String, earendil_lownet::InLinkConfig>,
    )>,
    pub out_links: BTreeMap<String, earendil_lownet::OutLinkConfig>,
    pub db_path: PathBuf,
    pub exit_info: Option<ExitInfo>,
    pub privacy_config: PrivacyConfig,
}
