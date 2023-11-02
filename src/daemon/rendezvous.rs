use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use earendil_crypt::{IdentityPublic, IdentitySecret};
use earendil_packet::Dock;
use serde::{Deserialize, Serialize};
use stdcode::StdcodeSerializeExt;

pub const HAVEN_FORWARD_DOCK: Dock = 100002;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForwardRequest {
    pub identity_pk: IdentityPublic,
    pub sig: Bytes,
    pub unix_timestamp: u64,
}

impl ForwardRequest {
    pub fn new(identity_sk: IdentitySecret) -> Self {
        let mut reg = Self {
            identity_pk: identity_sk.public(),
            sig: Bytes::new(),
            unix_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        reg.sig = identity_sk.sign(reg.to_sign().as_bytes());
        reg
    }

    pub fn to_sign(&self) -> blake3::Hash {
        let mut this = self.clone();
        this.sig = Bytes::new();
        blake3::keyed_hash(b"haven_registration______________", &this.stdcode())
    }
}
