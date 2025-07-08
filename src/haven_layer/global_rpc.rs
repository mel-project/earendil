mod server;
mod transport;

use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
pub use server::GlobalRpcImpl;
use stdcode::StdcodeSerializeExt;
pub use transport::GlobalRpcTransport;

use async_trait::async_trait;

use earendil_crypt::{AnonEndpoint, HavenFingerprint, HavenIdentitySecret};
use earendil_crypt::{HavenIdentityPublic, VerifyError};
use earendil_packet::Dock;

use nanorpc::nanorpc_derive;

use super::dht::HavenLocator;

pub const GLOBAL_RPC_DOCK: Dock = 100001;

#[nanorpc_derive]
#[async_trait]
pub trait GlobalRpcProtocol {
    async fn ping(&self, i: u64) -> u64;

    async fn dht_insert(&self, locator: HavenLocator);

    async fn dht_get(&self, key: HavenFingerprint) -> Option<HavenLocator>;

    async fn alloc_forward(&self, forward_req: RegisterHavenReq) -> Result<(), VerifyError>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterHavenReq {
    pub anon_id: AnonEndpoint,
    pub identity_pk: HavenIdentityPublic,
    pub port: u16,
    pub sig: Bytes,
    pub unix_timestamp: u64,
}

impl RegisterHavenReq {
    pub fn new(my_anon_id: AnonEndpoint, identity_sk: HavenIdentitySecret, port: u16) -> Self {
        let mut reg = Self {
            anon_id: my_anon_id,
            identity_pk: identity_sk.public(),
            port,
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
