pub mod server;
pub mod transport;

use async_trait::async_trait;

use earendil_crypt::Fingerprint;
use earendil_packet::Dock;

use nanorpc::nanorpc_derive;

use super::haven::HavenLocator;

pub const GLOBAL_RPC_DOCK: Dock = 100001;

#[nanorpc_derive]
#[async_trait]
pub trait GlobalRpcProtocol {
    async fn ping(&self, i: u64) -> u64;

    async fn dht_insert(&self, key: Fingerprint, value: HavenLocator, recurse: bool);

    async fn dht_get(&self, key: Fingerprint, recurse: bool) -> Option<HavenLocator>;
}
