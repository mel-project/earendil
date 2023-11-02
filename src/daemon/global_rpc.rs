pub mod server;
pub mod transport;

use async_trait::async_trait;

use earendil_crypt::Fingerprint;
use earendil_crypt::VerifyError;
use earendil_packet::Dock;

use nanorpc::nanorpc_derive;

use crate::control_protocol::DhtError;

use super::haven::HavenLocator;
use super::rendezvous::ForwardRequest;

pub const GLOBAL_RPC_DOCK: Dock = 100001;

#[nanorpc_derive]
#[async_trait]
pub trait GlobalRpcProtocol {
    async fn ping(&self, i: u64) -> u64;

    async fn dht_insert(&self, locator: HavenLocator, recurse: bool) -> Result<(), DhtError>;

    async fn dht_get(
        &self,
        key: Fingerprint,
        recurse: bool,
    ) -> Result<Option<HavenLocator>, DhtError>;

    async fn alloc_forward(&self, forward_req: ForwardRequest) -> Result<(), VerifyError>;
}
