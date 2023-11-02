use async_trait::async_trait;

use crate::control_protocol::DhtError;
use crate::daemon::rendezvous::ForwardRequest;
use crate::daemon::{haven::HavenLocator, DaemonContext};
use earendil_crypt::{Fingerprint, VerifyError};

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

    async fn dht_insert(&self, locator: HavenLocator, recurse: bool) -> Result<(), DhtError> {
        let key = locator.identity_pk.fingerprint();

        if recurse {
            self.ctx.dht_insert(locator).await
        } else {
            locator
                .identity_pk
                .verify(&locator.signable(), &locator.signature)?;

            log::debug!("inserting key {key} locally");
            self.ctx.dht_cache.insert(key, locator.clone());
        }
        Ok(())
    }

    async fn dht_get(
        &self,
        key: Fingerprint,
        recurse: bool,
    ) -> Result<Option<HavenLocator>, DhtError> {
        if let Some(val) = self.ctx.dht_cache.get(&key) {
            return Ok(Some(val));
        } else if recurse {
            log::debug!("searching DHT for {key}");
            return self.ctx.dht_get(key).await;
        }
        Ok(None)
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
