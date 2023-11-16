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
use earendil_topology::RelayGraph;
use futures_util::{stream::FuturesUnordered, StreamExt};
use moka::sync::{Cache, CacheBuilder};
use parking_lot::{Mutex, RwLock};
use smol::channel::Sender;
use smol_timeout::TimeoutExt;
use stdcode::StdcodeSerializeExt;

use crate::{
    config::ConfigFile,
    control_protocol::{DhtError, SendMessageError},
    daemon::route_to_instructs,
    havens::haven::HavenLocator,
    sockets::socket::Endpoint,
    utils::get_or_create_id,
};

use super::{
    global_rpc::{transport::GlobalRpcTransport, GlobalRpcClient},
    neightable::NeighTable,
    reply_block_store::ReplyBlockStore,
    DHT_REDUNDANCY,
};

#[derive(Clone)]
pub struct DaemonContext {
    pub config: Arc<ConfigFile>,
    pub table: Arc<NeighTable>,
    pub identity: Arc<IdentitySecret>,
    pub onion_sk: OnionSecret,
    pub relay_graph: Arc<RwLock<RelayGraph>>,
    pub degarblers: Cache<u64, ReplyDegarbler>,
    pub anon_destinations: Arc<Mutex<ReplyBlockStore>>,
    pub socket_recv_queues: Arc<DashMap<Endpoint, Sender<(Message, Fingerprint)>>>,
    pub haven_dht: Cache<Fingerprint, HavenLocator>,
    pub registered_havens: Arc<Cache<Fingerprint, ()>>,
}

impl DaemonContext {
    pub(crate) fn new(config: ConfigFile) -> anyhow::Result<Self> {
        let table = Arc::new(NeighTable::new());
        let identity = get_or_create_id(&config.identity)?;
        let ctx = DaemonContext {
            config: Arc::new(config),
            table: table.clone(),
            identity: identity.into(),
            onion_sk: OnionSecret::generate(),
            relay_graph: Arc::new(RwLock::new(RelayGraph::new())),
            degarblers: Cache::new(1_000_000),
            anon_destinations: Arc::new(Mutex::new(ReplyBlockStore::new())),

            socket_recv_queues: Arc::new(DashMap::new()),
            haven_dht: CacheBuilder::default()
                .time_to_idle(Duration::from_secs(60 * 60))
                .build(),
            registered_havens: Arc::new(
                Cache::builder()
                    .max_capacity(100_000)
                    .time_to_idle(Duration::from_secs(60 * 60))
                    .build(),
            ),
        };

        Ok(ctx)
    }

    pub async fn send_message(
        &self,
        src_anon_id: Option<IdentitySecret>,
        src_dock: Dock,
        dst_fp: Fingerprint,
        dst_dock: Dock,
        content: Bytes,
    ) -> Result<(), SendMessageError> {
        let now = Instant::now();
        let _guard = scopeguard::guard((), |_| {
            let send_msg_time = now.elapsed().as_millis();
            log::debug!("SEND MESSAGE TOOK:::::::::: {send_msg_time}");
        });

        let (public_isk, my_anon_osk) = if let Some(anon_id) = src_anon_id {
            (Arc::new(anon_id), Some(OnionSecret::generate()))
        } else {
            (self.identity.clone(), None)
        };

        let maybe_reply_block = self.anon_destinations.lock().pop(&dst_fp);
        if let Some(reply_block) = maybe_reply_block {
            if my_anon_osk.is_some() {
                return Err(SendMessageError::NoAnonId);
            }
            log::debug!("sending message with reply block");
            let inner = InnerPacket::Message(Message::new(src_dock, dst_dock, content));
            let raw_packet = RawPacket::new_reply(&reply_block, inner, &public_isk)?;
            self.table.inject_asif_incoming(raw_packet).await;
        } else {
            let route = self
                .relay_graph
                .read()
                .find_shortest_path(&self.identity.public().fingerprint(), &dst_fp)
                .ok_or(SendMessageError::NoRoute)?;
            log::debug!("building a normal N2R message with route {:?}", route);
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
                &public_isk,
            )?;
            // we send the onion by treating it as a message addressed to ourselves
            self.table.inject_asif_incoming(wrapped_onion).await;

            // if we want to use an anon source, send a batch of reply blocks
            // TODO this should be replaced
            if let Some(my_anon_osk) = my_anon_osk {
                // currently the path for every one of them is the same; will want to change this in the future
                let n = 8;
                let reverse_route = self
                    .relay_graph
                    .read()
                    .find_shortest_path(&dst_fp, &self.identity.public().fingerprint())
                    .ok_or(SendMessageError::NoRoute)?;
                let reverse_instructs =
                    route_to_instructs(reverse_route, self.relay_graph.clone())?;
                // log::debug!("reverse_instructs = {:?}", reverse_instructs);

                let mut rbs: Vec<ReplyBlock> = vec![];
                for _ in 0..n {
                    let (rb, (id, degarbler)) = ReplyBlock::new(
                        &reverse_instructs,
                        &self.onion_sk.public(),
                        my_anon_osk.clone(),
                        (*public_isk).clone(),
                    )
                    .map_err(|_| SendMessageError::ReplyBlockFailed)?;
                    rbs.push(rb);
                    self.degarblers.insert(id, degarbler);
                }
                let wrapped_rb_onion = RawPacket::new_normal(
                    &instructs,
                    &their_opk,
                    InnerPacket::ReplyBlocks(rbs),
                    &public_isk,
                )?;
                // we send the onion by treating it as a message addressed to ourselves
                self.table.inject_asif_incoming(wrapped_rb_onion).await;
            }
        }
        Ok(())
    }

    fn dht_key_to_fps(&self, key: &str) -> Vec<Fingerprint> {
        let mut all_nodes: Vec<Fingerprint> = self.relay_graph.read().all_nodes().collect();
        all_nodes.sort_unstable_by_key(|fp| *blake3::hash(&(key, fp).stdcode()).as_bytes());
        all_nodes
    }

    pub async fn dht_insert(&self, locator: HavenLocator) {
        let key = locator.identity_pk.fingerprint();
        let replicas = self.dht_key_to_fps(&key.to_string());
        let anon_isk = Some(IdentitySecret::generate());

        for replica in replicas.into_iter().take(DHT_REDUNDANCY) {
            log::debug!("key {key} inserting into remote replica {replica}");
            let gclient = GlobalRpcClient(GlobalRpcTransport::new(
                self.clone(),
                anon_isk.clone(),
                replica,
            ));
            match gclient
                .dht_insert(locator.clone(), false)
                .timeout(Duration::from_secs(60))
                .await
            {
                Some(Err(e)) => log::debug!("inserting {key} into {replica} failed: {:?}", e),
                None => log::debug!("inserting {key} into {replica} timed out"),
                _ => {}
            }
        }
    }

    pub async fn dht_get(
        &self,
        fingerprint: Fingerprint,
    ) -> Result<Option<HavenLocator>, DhtError> {
        if let Some(locator) = self.haven_dht.get(&fingerprint) {
            return Ok(Some(locator));
        };
        let replicas = self.dht_key_to_fps(&fingerprint.to_string());
        let mut gatherer = FuturesUnordered::new();
        let anon_isk = Some(IdentitySecret::generate());
        for replica in replicas.into_iter().take(DHT_REDUNDANCY) {
            let anon_isk = anon_isk.clone();
            gatherer.push(async move {
                let gclient =
                    GlobalRpcClient(GlobalRpcTransport::new(self.clone(), anon_isk, replica));
                anyhow::Ok(
                    gclient
                        .dht_get(fingerprint, false)
                        .timeout(Duration::from_secs(30))
                        .await
                        .context("timed out")??,
                )
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
                        self.haven_dht.insert(fingerprint, locator.clone());
                        return Ok(Some(locator));
                    }
                }
            }
        }
        Ok(None)
    }
}
