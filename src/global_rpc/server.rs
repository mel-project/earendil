use std::time::Duration;

use async_trait::async_trait;
use moka::sync::Cache;

use crate::{
    bicache::Bicache,
    context::{CtxField, DaemonContext},
    control_protocol::DhtError,
    daemon::dht::{dht_get, dht_insert},
    haven_util::{HavenLocator, RegisterHavenReq},
};
use earendil_crypt::{AnonRemote, HavenFingerprint, VerifyError};

use super::GlobalRpcProtocol;

pub struct GlobalRpcImpl {
    ctx: DaemonContext,
}

impl GlobalRpcImpl {
    pub fn new(ctx: DaemonContext) -> GlobalRpcImpl {
        GlobalRpcImpl { ctx }
    }
}

static LOCAL_DHT_SHARD: CtxField<Cache<HavenFingerprint, HavenLocator>> = |_| {
    Cache::builder()
        .time_to_live(Duration::from_secs(600))
        .build()
};

pub static REGISTERED_HAVENS: CtxField<Bicache<AnonRemote, HavenFingerprint>> =
    |_| Bicache::new(3600);

#[async_trait]
impl GlobalRpcProtocol for GlobalRpcImpl {
    async fn ping(&self, i: u64) -> u64 {
        i
    }

    async fn dht_insert(&self, locator: HavenLocator, recurse: bool) -> Result<(), DhtError> {
        let key = locator.identity_pk.fingerprint();

        if recurse {
            dht_insert(&self.ctx, locator).await
        } else {
            locator
                .identity_pk
                .verify(&locator.to_sign(), &locator.signature)
                .map_err(|_| DhtError::VerifyFailed)?;
            self.ctx.get(LOCAL_DHT_SHARD).insert(key, locator.clone());
        }
        Ok(())
    }

    async fn dht_get(
        &self,
        key: HavenFingerprint,
        recurse: bool,
    ) -> Result<Option<HavenLocator>, DhtError> {
        if let Some(val) = self.ctx.get(LOCAL_DHT_SHARD).get(&key) {
            return Ok(Some(val));
        } else if recurse {
            tracing::debug!("searching DHT for {key}");
            return dht_get(&self.ctx, key).await;
        }
        Ok(None)
    }

    async fn alloc_forward(&self, registration: RegisterHavenReq) -> Result<(), VerifyError> {
        registration
            .identity_pk
            .verify(registration.to_sign().as_bytes(), &registration.sig)?;
        self.ctx
            .get(REGISTERED_HAVENS)
            .insert(registration.anon_id, registration.identity_pk.fingerprint());
        Ok(())
    }
}
