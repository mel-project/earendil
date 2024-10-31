use bytes::Bytes;
use earendil_crypt::{
    HavenFingerprint, HavenIdentityPublic, HavenIdentitySecret, RelayFingerprint,
};
use earendil_packet::crypt::DhPublic;

use futures_util::stream::FuturesUnordered;
use serde::{Deserialize, Serialize};

use smol::stream::StreamExt;
use stdcode::StdcodeSerializeExt;

use crate::v2h_node::global_rpc::{GlobalRpcClient, GlobalRpcTransport};

use super::V2hNodeCtx;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HavenLocator {
    pub identity_pk: HavenIdentityPublic,
    pub onion_pk: DhPublic,
    pub rendezvous_point: RelayFingerprint,
    pub signature: Bytes,
}

impl HavenLocator {
    pub fn new(
        identity_sk: HavenIdentitySecret,
        onion_pk: DhPublic,
        rendezvous_fingerprint: RelayFingerprint,
    ) -> HavenLocator {
        let identity_pk = identity_sk.public();
        let locator = HavenLocator {
            identity_pk,
            onion_pk,
            rendezvous_point: rendezvous_fingerprint,
            signature: Bytes::new(),
        };
        let signature = identity_sk.sign(&locator.to_sign());

        HavenLocator {
            identity_pk,
            onion_pk,
            rendezvous_point: rendezvous_fingerprint,
            signature,
        }
    }

    pub fn to_sign(&self) -> [u8; 32] {
        let locator = HavenLocator {
            identity_pk: self.identity_pk,
            onion_pk: self.onion_pk,
            rendezvous_point: self.rendezvous_point,
            signature: Bytes::new(),
        };
        let hash = blake3::keyed_hash(b"haven_locator___________________", &locator.stdcode());

        *hash.as_bytes()
    }
}

const DHT_REDUNDANCY: usize = 3;

/// Insert a locator into the DHT.
pub async fn dht_insert(ctx: &V2hNodeCtx, locator: HavenLocator) {
    let key = locator.identity_pk.fingerprint();
    let replicas = dht_key_to_fps(ctx, &key.to_string());
    let mut gatherer = FuturesUnordered::new();

    for replica in replicas.into_iter().take(DHT_REDUNDANCY) {
        let locator = locator.clone();
        let gclient = GlobalRpcClient(GlobalRpcTransport::new(replica, ctx.n2r.bind_anon()));
        gatherer.push(async move {
            tracing::trace!("key {key} inserting into remote replica {replica}");
            anyhow::Ok(gclient.dht_insert(locator.clone()).await?)
        })
    }
    while let Some(res) = gatherer.next().await {
        match res {
            Ok(_) => (),
            Err(e) => tracing::debug!("DHT insert failed! {e}"),
        }
    }
}

/// Obtain a locator from the DHT.
pub async fn dht_get(
    ctx: &V2hNodeCtx,
    fingerprint: HavenFingerprint,
) -> anyhow::Result<Option<HavenLocator>> {
    // TODO: DHT cache

    let replicas = dht_key_to_fps(ctx, &fingerprint.to_string());

    let mut gatherer = FuturesUnordered::new();
    for replica in replicas.into_iter().take(DHT_REDUNDANCY) {
        let n2r_skt = ctx.n2r.bind_anon();
        tracing::debug!("[dht_get]: n2r_skt: {}", n2r_skt.local_endpoint());
        gatherer.push(async move {
            let gclient = GlobalRpcClient(GlobalRpcTransport::new(replica, n2r_skt));
            anyhow::Ok(gclient.dht_get(fingerprint).await?)
        })
    }
    let mut retval = Ok(None);
    while let Some(result) = gatherer.next().await {
        match result {
            Err(err) => retval = Err(anyhow::anyhow!("network error: {err}")),
            Ok(None) => continue,
            Ok(Some(locator)) => {
                tracing::debug!("got locator");
                let id_pk = locator.identity_pk;
                let payload = locator.to_sign();
                if id_pk.fingerprint() == fingerprint {
                    id_pk.verify(&payload, &locator.signature)?;
                    return Ok(Some(locator));
                } else {
                    retval = Err(anyhow::anyhow!("verification failed for DHT entry"));
                }
            }
        }
    }
    retval
}

fn dht_key_to_fps(ctx: &V2hNodeCtx, key: &str) -> Vec<RelayFingerprint> {
    let mut all_nodes: Vec<RelayFingerprint> = ctx
        .n2r
        .link_node()
        .netgraph()
        .read_graph(|g| g.all_nodes().collect());
    all_nodes.sort_unstable_by_key(|fp| *blake3::hash(&(key, fp).stdcode()).as_bytes());
    all_nodes
}
