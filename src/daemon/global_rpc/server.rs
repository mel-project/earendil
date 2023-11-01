use std::time::Duration;

use async_trait::async_trait;
use moka::sync::{Cache, CacheBuilder};

use crate::daemon::DaemonContext;

use super::GlobalRpcProtocol;

pub struct GlobalRpcImpl {
    ctx: DaemonContext,
    dht_cache: Cache<String, String>,
}

impl GlobalRpcImpl {
    pub fn new(ctx: DaemonContext) -> GlobalRpcImpl {
        GlobalRpcImpl {
            ctx,
            dht_cache: CacheBuilder::default()
                .time_to_idle(Duration::from_secs(30))
                .build(),
        }
    }
}

#[async_trait]
impl GlobalRpcProtocol for GlobalRpcImpl {
    async fn ping(&self, i: u64) -> u64 {
        i
    }

    async fn dht_insert(&self, key: String, value: String, recurse: bool) {
        // insert into local cache first
        self.dht_cache.insert(key.clone(), value.clone());
        log::debug!("key {key} inserted into local DHT");

        if recurse {
            log::debug!("inserting key {key} into remote DHT");
            self.ctx.dht_insert(key, value).await
        }
    }

    async fn dht_get(&self, key: String, recurse: bool) -> Option<String> {
        if let Some(val) = self.dht_cache.get(&key) {
            return Some(val);
        } else if recurse {
            log::debug!("no local value for {key}, searching remote DHT");
            return self.ctx.dht_get(key).await;
        }
        None
    }
}
