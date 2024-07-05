use async_trait::async_trait;

use moka::sync::Cache;

use crate::v2h_node::{dht::HavenLocator, V2hNodeCtx};
use earendil_crypt::{HavenFingerprint, VerifyError};

use super::{GlobalRpcProtocol, RegisterHavenReq};

pub struct GlobalRpcImpl {
    ctx: V2hNodeCtx,

    local_dht_shard: Cache<HavenFingerprint, HavenLocator>,
}

impl GlobalRpcImpl {
    pub fn new(ctx: V2hNodeCtx) -> GlobalRpcImpl {
        GlobalRpcImpl {
            ctx,

            local_dht_shard: Cache::new(5000),
        }
    }
}

#[async_trait]
impl GlobalRpcProtocol for GlobalRpcImpl {
    async fn ping(&self, i: u64) -> u64 {
        i
    }

    async fn dht_insert(&self, locator: HavenLocator) {
        let key = locator.identity_pk.fingerprint();

        if locator
            .identity_pk
            .verify(&locator.to_sign(), &locator.signature)
            .is_ok()
        {
            self.local_dht_shard.insert(key, locator.clone());
            tracing::debug!("inserted dht entry for haven {key}");
        } else {
            tracing::error!("Invalid locator signature");
        }
    }

    async fn dht_get(&self, key: HavenFingerprint) -> Option<HavenLocator> {
        self.local_dht_shard.get(&key)
    }

    async fn alloc_forward(&self, registration: RegisterHavenReq) -> Result<(), VerifyError> {
        tracing::trace!("received alloc_forward request");
        registration
            .identity_pk
            .verify(registration.to_sign().as_bytes(), &registration.sig)?;
        self.ctx
            .registered_havens
            .insert(registration.anon_id, registration.identity_pk.fingerprint());
        tracing::trace!("successfully registered haven");
        Ok(())
    }
}
