use async_trait::async_trait;
use earendil_crypt::Fingerprint;

use crate::daemon::{haven::HavenLocator, DaemonContext};

use super::GlobalRpcProtocol;

pub struct GlobalRpcImpl {
    ctx: DaemonContext,
}

impl GlobalRpcImpl {
    pub fn new(ctx: DaemonContext) -> GlobalRpcImpl {
        GlobalRpcImpl { ctx }
    }
}

#[async_trait]
impl GlobalRpcProtocol for GlobalRpcImpl {
    async fn ping(&self, i: u64) -> u64 {
        i
    }

    async fn dht_insert(&self, key: Fingerprint, value: HavenLocator, recurse: bool) {
        if recurse {
            self.ctx.dht_insert(key, value).await
        } else {
            log::debug!("inserting key {key} locally");
            self.ctx.dht_cache.insert(key, value.clone());
        }
    }

    async fn dht_get(&self, key: Fingerprint, recurse: bool) -> Option<HavenLocator> {
        if let Some(val) = self.ctx.dht_cache.get(&key) {
            return Some(val);
        } else if recurse {
            log::debug!("searching DHT for {key}");
            return self.ctx.dht_get(key).await;
        }
        None
    }
}
