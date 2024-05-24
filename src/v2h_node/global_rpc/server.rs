use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use moka::sync::Cache;
use serde::{Deserialize, Serialize};

use crate::{
    context::{CtxField, DaemonContext},
    control_protocol::DhtError,
    dht::{dht_get, dht_insert},
    n2r_node::N2rAnonSocket,
    v2h_node::{dht::HavenLocator, V2hNodeCtx},
};
use earendil_crypt::{
    AnonEndpoint, HavenFingerprint, HavenIdentityPublic, HavenIdentitySecret, VerifyError,
};

use super::{bicache::Bicache, GlobalRpcProtocol, RegisterHavenReq};

pub struct GlobalRpcImpl {
    ctx: V2hNodeCtx,
    n2r_skt: N2rAnonSocket,

    registered_havens: Bicache<AnonEndpoint, HavenFingerprint>,

    local_dht_shard: Cache<HavenFingerprint, HavenLocator>,
}

impl GlobalRpcImpl {
    pub fn new(ctx: V2hNodeCtx, n2r_skt: N2rAnonSocket) -> GlobalRpcImpl {
        GlobalRpcImpl {
            ctx,
            n2r_skt,

            registered_havens: Bicache::new(3600),
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
        } else {
            tracing::error!("Invalid locator signature");
        }
    }

    async fn dht_get(&self, key: HavenFingerprint) -> Option<HavenLocator> {
        self.local_dht_shard.get(&key)
    }

    async fn alloc_forward(&self, registration: RegisterHavenReq) -> Result<(), VerifyError> {
        registration
            .identity_pk
            .verify(registration.to_sign().as_bytes(), &registration.sig)?;
        self.registered_havens
            .insert(registration.anon_id, registration.identity_pk.fingerprint());
        Ok(())
    }
}
