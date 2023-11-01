use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use earendil_crypt::{Fingerprint, IdentityPublic, IdentitySecret};
use earendil_packet::Dock;
use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use stdcode::StdcodeSerializeExt;

pub const HAVEN_FORWARD_DOCK: Dock = 100002;

pub struct ForwardTable {
    dests: Cache<Fingerprint, ()>,
    seen_srcs: Cache<Fingerprint, Fingerprint>,
}

impl ForwardTable {
    pub fn new() -> Self {
        let dests = Cache::builder()
            .max_capacity(100_000)
            .time_to_idle(Duration::from_secs(3600))
            .build();
        let seen_srcs = Cache::builder()
            .max_capacity(100_000)
            .time_to_idle(Duration::from_secs(3600))
            .build();
        Self { dests, seen_srcs }
    }

    pub fn is_dest(&self, haven_fp: &Fingerprint) -> bool {
        self.dests.contains_key(haven_fp)
    }

    pub fn is_seen_src(&self, client_fp: &Fingerprint) -> bool {
        self.seen_srcs.contains_key(client_fp)
    }

    pub fn insert_dest(&self, haven_fp: Fingerprint) {
        self.dests.insert(haven_fp, ())
    }

    pub fn insert_src(&self, client_endpoint: Fingerprint, haven_fp: Fingerprint) {
        self.seen_srcs.insert(client_endpoint, haven_fp)
    }
}

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
