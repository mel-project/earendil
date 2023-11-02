use anyhow::Context;
use async_trait::async_trait;
use earendil_crypt::{Fingerprint, VerifyError};
use futures_util::{stream::FuturesUnordered, StreamExt};
use moka::sync::{Cache, CacheBuilder};
use serde::{Deserialize, Serialize};
use smol_timeout::TimeoutExt;
use std::time::Duration;
use stdcode::StdcodeSerializeExt;
use thiserror::Error;

use crate::daemon::{
    global_rpc::{transport::GlobalRpcTransport, GlobalRpcClient},
    rendezvous::ForwardRequest,
    DaemonContext,
};

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

    fn dht_key_to_fps(&self, key: &str) -> Vec<Fingerprint> {
        let mut all_nodes: Vec<Fingerprint> = self.ctx.relay_graph.read().all_nodes().collect();
        all_nodes.sort_unstable_by_key(|fp| *blake3::hash(&(key, fp).stdcode()).as_bytes());
        all_nodes
    }
}

const DHT_REDUNDANCY: usize = 3;

#[async_trait]
impl GlobalRpcProtocol for GlobalRpcImpl {
    async fn ping(&self, i: u64) -> u64 {
        i
    }

    async fn dht_insert(&self, key: String, value: String, recurse: bool) {
        let replicas = self.dht_key_to_fps(&key);

        for replica in replicas.into_iter().take(DHT_REDUNDANCY) {
            if replica == self.ctx.identity.public().fingerprint() {
                log::debug!("key {key} inserting into ourselves!");
                self.dht_cache.insert(key.clone(), value.clone());
            } else if recurse {
                log::debug!("key {key} inserting into remote replica {replica}");
                let gclient = GlobalRpcClient(GlobalRpcTransport::new(self.ctx.clone(), replica));
                match gclient
                    .dht_insert(key.clone(), value.clone(), false)
                    .timeout(Duration::from_secs(10))
                    .await
                {
                    Some(Err(e)) => log::debug!("inserting {key} into {replica} failed: {:?}", e),
                    None => log::debug!("inserting {key} into {replica} timed out"),
                    _ => {}
                }
            }
        }
    }

    async fn dht_get(&self, key: String, recurse: bool) -> Option<String> {
        if let Some(val) = self.dht_cache.get(&key) {
            return Some(val);
        } else if recurse {
            let replicas = self.dht_key_to_fps(&key);
            let mut gatherer = FuturesUnordered::new();
            for replica in replicas.into_iter().take(DHT_REDUNDANCY) {
                let key = key.clone();
                gatherer.push(async move {
                    let gclient =
                        GlobalRpcClient(GlobalRpcTransport::new(self.ctx.clone(), replica));
                    anyhow::Ok(
                        gclient
                            .dht_get(key, false)
                            .timeout(Duration::from_secs(30))
                            .await
                            .context("timed out")??,
                    )
                })
            }
            while let Some(result) = gatherer.next().await {
                match result {
                    Err(err) => log::warn!("error while dht_get: {:?}", err),
                    Ok(None) => continue,
                    Ok(Some(val)) => return Some(val),
                }
            }
        }
        None
    }

    async fn alloc_forward(&self, registration: ForwardRequest) -> Result<(), VerifyError> {
        registration
            .identity_pk
            .verify(registration.to_sign().as_bytes(), &registration.sig)?;
        self.ctx
            .registered_havens
            .insert(registration.identity_pk.fingerprint(), ());
        Ok(())
    }
}
