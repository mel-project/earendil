use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use bytes::Bytes;
use dashmap::DashMap;
use earendil_crypt::{Fingerprint, IdentitySecret};
use earendil_packet::{
    crypt::OnionSecret, Dock, InnerPacket, Message, RawPacket, ReplyBlock, ReplyDegarbler,
};
use earendil_topology::{IdentityDescriptor, RelayGraph};
use futures_util::{stream::FuturesUnordered, StreamExt};
use itertools::Itertools;
use moka::sync::{Cache, CacheBuilder};
use once_cell::sync::Lazy;
use parking_lot::{Mutex, RwLock};
use smol::channel::Sender;
use smol_timeout::TimeoutExt;
use stdcode::StdcodeSerializeExt;

use crate::{
    config::ConfigFile,
    control_protocol::{DhtError, SendMessageError},
    daemon::route_to_instructs,
    global_rpc::{transport::GlobalRpcTransport, GlobalRpcClient},
    haven::HavenLocator,
    socket::Endpoint,
};

use super::{neightable::NeighTable, reply_block_store::ReplyBlockStore};

const DHT_REDUNDANCY: usize = 3;

/// This does most of the housekeeping for the daemon state.
#[derive(Clone)]
pub struct DaemonContext {
    pub config: Arc<ConfigFile>,
    pub table: Arc<NeighTable>,
    pub identity: IdentitySecret,
    pub onion_sk: OnionSecret,
    pub relay_graph: Arc<RwLock<RelayGraph>>,
    pub degarblers: Cache<u64, ReplyDegarbler>,
    pub anon_destinations: Arc<Mutex<ReplyBlockStore>>,
    pub socket_recv_queues: Arc<DashMap<Endpoint, Sender<(Message, Fingerprint)>>>,
    pub local_rdht_shard: Cache<Fingerprint, HavenLocator>,
    pub rdht_cache: Cache<Fingerprint, HavenLocator>,
    pub registered_havens: Arc<Cache<Fingerprint, ()>>,

    remote_rb_balance: Cache<(IdentitySecret, Fingerprint), f64>,
}

impl DaemonContext {
    pub fn new(config: ConfigFile) -> anyhow::Result<Self> {
        let table = Arc::new(NeighTable::new());
        let identity = if let Some(seed) = &config.identity_seed {
            IdentitySecret::from_bytes(&earendil_crypt::kdf_from_human(seed, "identity_kdf_salt"))
        } else {
            IdentitySecret::generate()
        };
        let onion_sk = OnionSecret::generate();
        // set up the topology stuff for myself
        let relay_graph = Arc::new(RwLock::new(RelayGraph::new()));

        let ctx = DaemonContext {
            config: Arc::new(config),
            table: table.clone(),
            identity,
            onion_sk,
            relay_graph,
            degarblers: Cache::new(1_000_000),
            anon_destinations: Arc::new(Mutex::new(ReplyBlockStore::new())),

            socket_recv_queues: Arc::new(DashMap::new()),
            local_rdht_shard: CacheBuilder::default()
                .time_to_idle(Duration::from_secs(60 * 60))
                .build(),
            rdht_cache: CacheBuilder::default()
                .time_to_live(Duration::from_secs(60))
                .build(),
            registered_havens: Arc::new(
                Cache::builder()
                    .max_capacity(100_000)
                    .time_to_idle(Duration::from_secs(60 * 60))
                    .build(),
            ),

            remote_rb_balance: Cache::builder()
                .time_to_live(Duration::from_secs(60)) // we don't keep track beyond so if rb calculation is wrong, we don't get stuck for too long
                .build(),
        };

        Ok(ctx)
    }

    pub async fn send_message(
        &self,
        src_idsk: IdentitySecret,
        src_dock: Dock,
        dst_fp: Fingerprint,
        dst_dock: Dock,
        content: Vec<Bytes>,
    ) -> Result<(), SendMessageError> {
        let now = Instant::now();
        let _guard = scopeguard::guard((), |_| {
            let send_msg_time = now.elapsed();
            log::trace!("send message took {:?}", send_msg_time);
        });

        let src_anon = src_idsk != self.identity;

        let maybe_reply_block = self.anon_destinations.lock().pop(&dst_fp);
        if let Some(reply_block) = maybe_reply_block {
            if src_anon {
                return Err(SendMessageError::NoAnonId);
            }
            let inner = InnerPacket::Message(Message::new(src_dock, dst_dock, content));
            let raw_packet = RawPacket::new_reply(&reply_block, inner, &src_idsk)?;
            self.table.inject_asif_incoming(raw_packet).await;
        } else {
            let route = self
                .relay_graph
                .read()
                .find_shortest_path(&self.identity.public().fingerprint(), &dst_fp)
                .ok_or(SendMessageError::NoRoute(dst_fp))?;
            let instructs = route_to_instructs(route, self.relay_graph.clone())?;
            let their_opk = self
                .relay_graph
                .read()
                .identity(&dst_fp)
                .ok_or(SendMessageError::NoOnionPublic(dst_fp))?
                .onion_pk;
            let wrapped_onion = RawPacket::new_normal(
                &instructs,
                &their_opk,
                InnerPacket::Message(Message::new(src_dock, dst_dock, content)),
                &src_idsk,
            )?;

            // if anon source, send RBs
            if src_anon {
                self.replenish_reply_blocks(src_idsk, dst_fp).await?;
            }

            // we send the onion by treating it as a message addressed to ourselves
            self.table.inject_asif_incoming(wrapped_onion).await;
        }
        Ok(())
    }

    pub fn decrement_rrb_balance(&self, my_anon_isk: IdentitySecret, reply_source: Fingerprint) {
        // this is racy, but probably fine
        let new_balance = self.rb_balance(my_anon_isk, reply_source);
        self.remote_rb_balance
            .insert((my_anon_isk, reply_source), new_balance - 1.0);
    }

    pub async fn replenish_reply_blocks(
        &self,
        my_anon_isk: IdentitySecret,
        dst_fp: Fingerprint,
    ) -> Result<(), SendMessageError> {
        const BATCH_SIZE: usize = 10;
        while self.rb_balance(my_anon_isk, dst_fp) < 100.0 {
            self.send_reply_blocks(BATCH_SIZE, my_anon_isk, dst_fp)
                .await?;
            // we conservatively assume half get there
            self.remote_rb_balance.insert(
                (my_anon_isk, dst_fp),
                self.rb_balance(my_anon_isk, dst_fp) + (BATCH_SIZE / 2) as f64,
            );
        }
        Ok(())
    }

    fn rb_balance(&self, my_anon_isk: IdentitySecret, reply_source: Fingerprint) -> f64 {
        self.remote_rb_balance
            .get_with((my_anon_isk, reply_source), || 0.0)
    }

    pub async fn send_reply_blocks(
        &self,
        count: usize,
        my_anon_isk: IdentitySecret,
        dst_fp: Fingerprint,
    ) -> Result<(), SendMessageError> {
        static ONION_SK_CACHE: Lazy<Cache<Fingerprint, OnionSecret>> =
            Lazy::new(|| Cache::new(100000));
        let my_anon_osk = ONION_SK_CACHE.get_with(my_anon_isk.public().fingerprint(), || {
            OnionSecret::generate()
        });

        log::trace!("sending a batch of {count} reply blocks to {dst_fp}");

        let route = self
            .relay_graph
            .read()
            .find_shortest_path(&self.identity.public().fingerprint(), &dst_fp)
            .ok_or(SendMessageError::NoRoute(dst_fp))?;
        let their_opk = self
            .relay_graph
            .read()
            .identity(&dst_fp)
            .ok_or(SendMessageError::NoOnionPublic(dst_fp))?
            .onion_pk;
        let instructs = route_to_instructs(route.clone(), self.relay_graph.clone())?;
        // currently the path for every one of them is the same; will want to change this in the future
        let reverse_route = self
            .relay_graph
            .read()
            .find_shortest_path(&dst_fp, &self.identity.public().fingerprint())
            .ok_or(SendMessageError::NoRoute(dst_fp))?;
        let reverse_instructs = route_to_instructs(reverse_route, self.relay_graph.clone())?;

        let mut rbs: Vec<ReplyBlock> = vec![];
        for _ in 0..count {
            let (rb, (id, degarbler)) = ReplyBlock::new(
                &reverse_instructs,
                &self.onion_sk.public(),
                my_anon_osk.clone(),
                my_anon_isk,
            )
            .map_err(|_| SendMessageError::ReplyBlockFailed)?;
            rbs.push(rb);
            self.degarblers.insert(id, degarbler);
        }
        let wrapped_rb_onion = RawPacket::new_normal(
            &instructs,
            &their_opk,
            InnerPacket::ReplyBlocks(rbs),
            &my_anon_isk,
        )?;
        log::trace!(
            "inject_asif_incoming on route = {:?}",
            route.iter().map(|s| s.to_string()).collect_vec()
        );
        // we send the onion by treating it as a message addressed to ourselves
        self.table.inject_asif_incoming(wrapped_rb_onion).await;
        Ok(())
    }

    fn dht_key_to_fps(&self, key: &str) -> Vec<Fingerprint> {
        let mut all_nodes: Vec<Fingerprint> = self
            .relay_graph
            .read()
            .all_nodes()
            .filter(|fp| {
                self.relay_graph
                    .read()
                    .identity(fp)
                    .map_or(false, |id| id.is_relay)
            })
            .collect();
        all_nodes.sort_unstable_by_key(|fp| *blake3::hash(&(key, fp).stdcode()).as_bytes());
        all_nodes
    }

    pub async fn dht_insert(&self, locator: HavenLocator) {
        let key = locator.identity_pk.fingerprint();
        let replicas = self.dht_key_to_fps(&key.to_string());
        let anon_isk = IdentitySecret::generate();
        let mut gatherer = FuturesUnordered::new();

        for replica in replicas.into_iter().take(DHT_REDUNDANCY) {
            let locator = locator.clone();
            gatherer.push(async move {
                log::trace!("key {key} inserting into remote replica {replica}");
                let gclient =
                    GlobalRpcClient(GlobalRpcTransport::new(self.clone(), anon_isk, replica));
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

    pub async fn dht_get(
        &self,
        fingerprint: Fingerprint,
    ) -> Result<Option<HavenLocator>, DhtError> {
        if let Some(locator) = self.rdht_cache.get(&fingerprint) {
            return Ok(Some(locator));
        }
        let replicas = self.dht_key_to_fps(&fingerprint.to_string());
        let mut gatherer = FuturesUnordered::new();
        let anon_isk = IdentitySecret::generate();
        for replica in replicas.into_iter().take(DHT_REDUNDANCY) {
            gatherer.push(async move {
                let gclient =
                    GlobalRpcClient(GlobalRpcTransport::new(self.clone(), anon_isk, replica));
                anyhow::Ok(gclient.dht_get(fingerprint, false).await?)
            })
        }
        while let Some(result) = gatherer.next().await {
            match result {
                Err(err) => log::warn!("error while dht_get: {:?}", err),
                Ok(Err(err)) => log::warn!("error while dht_get: {:?}", err),
                Ok(Ok(None)) => continue,
                Ok(Ok(Some(locator))) => {
                    let id_pk = locator.identity_pk;
                    let payload = locator.to_sign();
                    if id_pk.fingerprint() == fingerprint {
                        id_pk.verify(&payload, &locator.signature)?;
                        self.rdht_cache.insert(fingerprint, locator.clone());
                        return Ok(Some(locator));
                    }
                }
            }
        }
        Ok(None)
    }
}
