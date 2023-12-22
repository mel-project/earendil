use std::time::Duration;

use anyhow::Context;
use earendil_crypt::{Fingerprint, IdentitySecret};
use futures_util::{stream::FuturesUnordered, StreamExt};
use moka::sync::{Cache, CacheBuilder};
use stdcode::StdcodeSerializeExt;

use crate::{
    control_protocol::DhtError,
    global_rpc::{transport::GlobalRpcTransport, GlobalRpcClient},
    haven_util::HavenLocator,
};

use super::context::{CtxField, DaemonContext, RELAY_GRAPH};

const DHT_REDUNDANCY: usize = 3;

static DHT_CACHE: CtxField<Cache<Fingerprint, HavenLocator>> = |_| {
    CacheBuilder::default()
        .time_to_live(Duration::from_secs(60))
        .build()
};

/// Insert a locator into the DHT.
pub async fn dht_insert(ctx: &DaemonContext, locator: HavenLocator) {
    let key = locator.identity_pk.fingerprint();
    let replicas = dht_key_to_fps(ctx, &key.to_string());
    let anon_isk = IdentitySecret::generate();
    let mut gatherer = FuturesUnordered::new();

    for replica in replicas.into_iter().take(DHT_REDUNDANCY) {
        let locator = locator.clone();
        gatherer.push(async move {
            log::trace!("key {key} inserting into remote replica {replica}");
            let gclient = GlobalRpcClient(GlobalRpcTransport::new(ctx.clone(), anon_isk, replica));
            anyhow::Ok(
                gclient
                    .dht_insert(locator.clone(), false)
                    .await
                    .context("DHT insert failed")??,
            )
        })
    }
    while let Some(res) = gatherer.next().await {
        match res {
            Ok(_) => log::debug!("DHT insert succeeded!"),
            Err(e) => log::debug!("DHT insert failed! {e}"),
        }
    }
}

/// Obtain a locator from the DHT.
pub async fn dht_get(
    ctx: &DaemonContext,
    fingerprint: Fingerprint,
) -> Result<Option<HavenLocator>, DhtError> {
    if let Some(locator) = ctx.get(DHT_CACHE).get(&fingerprint) {
        return Ok(Some(locator));
    }
    let replicas = dht_key_to_fps(ctx, &fingerprint.to_string());
    let mut gatherer = FuturesUnordered::new();
    let anon_isk = IdentitySecret::generate();
    for replica in replicas.into_iter().take(DHT_REDUNDANCY) {
        gatherer.push(async move {
            let gclient = GlobalRpcClient(GlobalRpcTransport::new(ctx.clone(), anon_isk, replica));
            anyhow::Ok(gclient.dht_get(fingerprint, false).await?)
        })
    }
    let mut retval = Ok(None);
    while let Some(result) = gatherer.next().await {
        match result {
            Err(err) => retval = Err(DhtError::NetworkFailure(err.to_string())),
            Ok(Err(err)) => retval = Err(err),
            Ok(Ok(None)) => continue,
            Ok(Ok(Some(locator))) => {
                let id_pk = locator.identity_pk;
                let payload = locator.to_sign();
                if id_pk.fingerprint() == fingerprint {
                    id_pk
                        .verify(&payload, &locator.signature)
                        .map_err(|_| DhtError::VerifyFailed)?;
                    ctx.get(DHT_CACHE).insert(fingerprint, locator.clone());
                    return Ok(Some(locator));
                } else {
                    retval = Err(DhtError::VerifyFailed);
                }
            }
        }
    }
    retval
}

fn dht_key_to_fps(ctx: &DaemonContext, key: &str) -> Vec<Fingerprint> {
    let mut all_nodes: Vec<Fingerprint> = ctx
        .get(RELAY_GRAPH)
        .read()
        .all_nodes()
        .filter(|fp| {
            ctx.get(RELAY_GRAPH)
                .read()
                .identity(fp)
                .map_or(false, |id| id.is_relay)
        })
        .collect();
    all_nodes.sort_unstable_by_key(|fp| *blake3::hash(&(key, fp).stdcode()).as_bytes());
    all_nodes
}
