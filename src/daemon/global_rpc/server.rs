use async_trait::async_trait;

use crate::daemon::DaemonContext;

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

    async fn dht_insert(&self, key: String, value: String, recurse: bool) {
        if recurse {
            self.ctx.dht_insert(key, value).await
        } else {
            log::debug!("inserting key {key} locally");
            self.ctx.dht_cache.insert(key.clone(), value.clone());
        }
    }

    async fn dht_get(&self, key: String, recurse: bool) -> Option<String> {
        if let Some(val) = self.ctx.dht_cache.get(&key) {
            return Some(val);
        } else if recurse {
            log::debug!("searching DHT for {key}");
            return self.ctx.dht_get(key).await;
        }
        None
    }
}
