use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use async_trait::async_trait;

use bytemuck::{Pod, Zeroable};
use bytes::Bytes;
use concurrent_queue::ConcurrentQueue;
use earendil_crypt::{ClientId, NeighborId, RelayFingerprint};
use earendil_packet::{RawBody, RawPacket};
use earendil_topology::{AdjacencyDescriptor, IdentityDescriptor};
use either::Either;
use futures_util::AsyncWriteExt;
use itertools::Itertools;
use moka::sync::{Cache, CacheBuilder};
use nanorpc::{JrpcRequest, JrpcResponse, RpcService, RpcTransport};
use nursery_macro::nursery;

use rand::{seq::SliceRandom, thread_rng, Rng};
use smol::{
    channel::Receiver,
    future::FutureExt,
    io::{AsyncBufReadExt, BufReader},
    stream::StreamExt,
};

use smol_timeout::TimeoutExt;
use sosistab2::Multiplex;
use tap::TapOptional;

use crate::{
    context::CtxField, daemon::inout_route::link_protocol::LinkClient, network::is_relay_neigh,
};
use crate::{
    context::{DaemonContext, MY_RELAY_IDENTITY, RELAY_GRAPH, SETTLEMENTS},
    network::incoming_raw,
};
use crate::{
    n2r::incoming_backward,
    settlement::{Seed, SettlementProof, SettlementRequest, SettlementResponse},
};

use super::link_protocol::{InfoResponse, LinkProtocol, LinkService};

const LABEL_LINK_RPC: &str = "link-rpc";
const LABEL_ONION: &str = "onion";

pub struct RelayNeighbor(
    pub Receiver<(RawPacket, RelayFingerprint)>,
    pub RelayFingerprint,
);

pub struct ClientNeighbor(pub Receiver<(RawBody, u64)>, pub ClientId);

pub struct LinkContext {
    pub ctx: DaemonContext,
    pub service: Arc<LinkService<LinkProtocolImpl>>,
    pub mplex: Arc<Multiplex>,
    pub neighbor: either::Either<RelayNeighbor, ClientNeighbor>,
}

pub async fn link_maintain(lctx: &LinkContext, is_listen: bool) -> anyhow::Result<()> {
    linkrpc_listen(lctx, is_listen)
        .race(async {
            if is_listen {
                smol::future::pending().await
            } else {
                loop {
                    let stream = lctx.mplex.open_conn(LABEL_ONION).await?;
                    handle_onion(lctx, stream).await?;
                }
            }
        })
        .await
        .inspect_err(|e| tracing::warn!("link_maintain died: {e}"))
}

async fn linkrpc_listen(lctx: &LinkContext, onion_listen: bool) -> anyhow::Result<()> {
    nursery!({
        loop {
            let mut stream = lctx.mplex.accept_conn().await?;
            match stream.label() {
                LABEL_LINK_RPC => spawn!(async move {
                    let mut stream_lines = BufReader::new(stream.clone()).lines();
                    while let Some(line) = stream_lines.next().await {
                        let line = line?;
                        let req: JrpcRequest = serde_json::from_str(&line)?;
                        // tracing::debug!(method = req.method, "LinkRPC request received");
                        let resp = lctx.service.respond_raw(req).await;
                        stream
                            .write_all((serde_json::to_string(&resp)? + "\n").as_bytes())
                            .await?;
                    }
                    anyhow::Ok(())
                })
                .detach(),
                LABEL_ONION if onion_listen => {
                    spawn!(handle_onion(lctx, stream)).detach();
                }
                other => tracing::warn!(label = other, onion_listen, "invalid link stream label"),
            }
        }
    })
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct PacketWithPeeler {
    pkt: RawPacket,
    peeler: RelayFingerprint,
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct RawBodyWithRbId {
    body: RawBody,
    rb_id: u64,
}

#[tracing::instrument(skip_all)]
async fn handle_onion(lctx: &LinkContext, conn: sosistab2::Stream) -> anyhow::Result<()> {
    let up = async {
        match lctx.neighbor.as_ref() {
            either::Either::Left(RelayNeighbor(recv_outgoing, _)) => loop {
                let (pkt, peeler) = recv_outgoing.recv().await?;
                let pkt_with_peeler = PacketWithPeeler { pkt, peeler };
                conn.send_urel(bytemuck::bytes_of(&pkt_with_peeler).to_vec().into())
                    .await?;
            },
            either::Either::Right(ClientNeighbor(recv_outgoing, _)) => loop {
                let (body, rb_id) = recv_outgoing.recv().await?;
                let raw_body_with_rb_id = RawBodyWithRbId { body, rb_id };
                conn.send_urel(bytemuck::bytes_of(&raw_body_with_rb_id).to_vec().into())
                    .await?;
            },
        }
    };

    let dn = async {
        let neigh_id = match lctx.neighbor.as_ref() {
            either::Either::Left(RelayNeighbor(_, id)) => NeighborId::Relay(*id),
            either::Either::Right(ClientNeighbor(_, id)) => NeighborId::Client(*id),
        };
        loop {
            if lctx.ctx.init().is_client() {
                let pkt = conn.recv_urel().await?;
                let RawBodyWithRbId { body, rb_id } = *bytemuck::try_from_bytes(&pkt)
                    .ok()
                    .context("incoming urel packet of the wrong size to be an onion packet")?;

                incoming_backward(&lctx.ctx, body, rb_id).await?;
            }
            // we are a relay
            else {
                let pkt = conn.recv_urel().await?;
                let PacketWithPeeler { pkt, peeler } = *bytemuck::try_from_bytes(&pkt)
                    .ok()
                    .context("incoming urel packet of the wrong size to be an onion packet")?;

                // if the neighbor is a relay
                incoming_raw(&lctx.ctx, neigh_id, peeler, pkt).await?;
            }
        }
    };

    up.race(dn).await
}

const POOL_TIMEOUT: Duration = Duration::from_secs(60);

type PooledConn = (BufReader<sosistab2::Stream>, sosistab2::Stream);

pub struct LinkRpcTransport {
    mplex: Arc<Multiplex>,
    conn_pool: ConcurrentQueue<(PooledConn, Instant)>,
}

impl LinkRpcTransport {
    /// Constructs a Multiplex-backed RpcTransport.
    pub fn new(mplex: Arc<Multiplex>) -> Self {
        Self {
            mplex,
            conn_pool: ConcurrentQueue::unbounded(),
        }
    }

    /// Obtains a free connection.
    async fn get_conn(&self) -> anyhow::Result<PooledConn> {
        while let Ok((stream, time)) = self.conn_pool.pop() {
            if time.elapsed() < POOL_TIMEOUT {
                return Ok(stream);
            }
        }
        let stream = self.mplex.open_conn(LABEL_LINK_RPC).await?;
        Ok((BufReader::with_capacity(65536, stream.clone()), stream))
    }
}

#[async_trait]
impl RpcTransport for LinkRpcTransport {
    type Error = anyhow::Error;

    async fn call_raw(&self, req: JrpcRequest) -> Result<JrpcResponse, Self::Error> {
        // Write and read a single line
        let mut conn = scopeguard::guard(self.get_conn().await?, |v| {
            let _ = self.conn_pool.push((v, Instant::now()));
        });
        conn.1
            .write_all((serde_json::to_string(&req)? + "\n").as_bytes())
            .await?;
        let mut b = String::new();
        conn.0.read_line(&mut b).await?;
        let resp: JrpcResponse = serde_json::from_str(&b)?;
        Ok(resp)
    }
}

pub struct LinkProtocolImpl {
    pub ctx: DaemonContext,
    pub mplex: Arc<Multiplex>,
    pub remote: either::Either<IdentityDescriptor, ClientId>,
    pub max_outgoing_price: u64,
}

#[async_trait]
impl LinkProtocol for LinkProtocolImpl {
    async fn info(&self) -> InfoResponse {
        InfoResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    #[tracing::instrument(skip(self))]
    async fn sign_adjacency(
        &self,
        mut left_incomplete: AdjacencyDescriptor,
    ) -> Option<AdjacencyDescriptor> {
        let my_sk = self
            .ctx
            .get(MY_RELAY_IDENTITY)
            .expect("only relays have global identities");
        let my_fp = my_sk.public().fingerprint();
        // This must be a neighbor that is "left" of us
        let valid = left_incomplete.left < left_incomplete.right
            && left_incomplete.right == my_fp
            && is_relay_neigh(&self.ctx, left_incomplete.left);
        if !valid {
            tracing::debug!("neighbor not right of us! Refusing to sign adjacency x_x");
            return None;
        }
        // Fill in the right-hand-side
        let signature = my_sk.sign(left_incomplete.to_sign().as_bytes());
        left_incomplete.right_sig = signature;

        self.ctx
            .get(RELAY_GRAPH)
            .write()
            .insert_adjacency(left_incomplete.clone())
            .map_err(|e| {
                tracing::warn!("could not insert here: {:?}", e);
                e
            })
            .ok()?;
        Some(left_incomplete)
    }

    async fn identity(&self, fp: RelayFingerprint) -> Option<IdentityDescriptor> {
        self.ctx.get(RELAY_GRAPH).read().identity(&fp)
    }

    #[tracing::instrument(skip(self))]
    async fn adjacencies(&self, fps: Vec<RelayFingerprint>) -> Vec<AdjacencyDescriptor> {
        let rg = self.ctx.get(RELAY_GRAPH).read();
        fps.into_iter()
            .flat_map(|fp| rg.adjacencies(&fp).into_iter().flatten())
            .dedup()
            .collect()
    }

    #[tracing::instrument(skip(self))]
    async fn client_push_price(&self, _price: u64, _debt_limit: u64) {
        todo!()
    }

    #[tracing::instrument(skip(self))]
    async fn relay_push_price(&self, _price: u64, _debt_limit: u64) {
        todo!()
    }

    #[tracing::instrument(skip(self))]
    async fn start_settlement(&self, req: SettlementRequest) -> Option<SettlementResponse> {
        let settlements = self.ctx.get(SETTLEMENTS);

        match req.payment_proof {
            SettlementProof::Automatic(_) => {
                tracing::debug!("handling auto_settlement req: {:?}", req);
                if let Ok(res) = settlements.verify_auto_settle(&self.ctx, req) {
                    res
                } else {
                    None
                }
            }
            SettlementProof::Manual => {
                tracing::debug!("handling manual settlement req: {:?}", req);
                let recv_res = settlements.insert_pending(req);

                if let Ok(recv_res) = recv_res {
                    match recv_res.recv().timeout(Duration::from_secs(300)).await {
                        Some(Ok(res)) => res,
                        Some(Err(e)) => {
                            log::warn!("settlement response receive error: {e}");
                            None
                        }
                        None => None,
                    }
                } else {
                    None
                }
            }
        }
    }

    #[tracing::instrument(skip(self))]
    async fn push_chat_client(&self, _msg: String) {
        todo!()
    }

    #[tracing::instrument(skip(self))]
    async fn push_chat_relay(&self, _msg: String) {
        todo!()
    }

    #[tracing::instrument(skip(self))]
    async fn request_seed(&self) -> Seed {
        let seed = rand::thread_rng().gen();
        let seed_cache = &self.ctx.get(SETTLEMENTS).seed_cache;
        let remote_fp = <itertools::Either<IdentityDescriptor, u64> as Clone>::clone(&self.remote)
            .left()
            .expect("REPLACE WITH PROPER ERROR HANDLING")
            .identity_pk
            .fingerprint();

        match seed_cache.get(&remote_fp) {
            Some(mut seeds) => {
                seeds.insert(seed);
                seed_cache.insert(remote_fp, seeds);
                seed
            }
            None => {
                let mut seed_set = HashSet::new();
                seed_set.insert(seed);
                seed_cache.insert(remote_fp, seed_set);
                seed
            }
        }
    }
}

#[tracing::instrument(skip(lctx))]
pub async fn gossip_loop(lctx: &LinkContext) -> anyhow::Result<()> {
    let link_rpc = LinkRpcTransport::new(lctx.mplex.clone());
    let link_client = LinkClient::from(link_rpc);
    let neigh_label = match lctx.neighbor {
        Either::Left(RelayNeighbor(_, fp)) => fp.to_string(),
        Either::Right(ClientNeighbor(_, id)) => id.to_string(),
    };

    loop {
        let once = async {
            if let Err(err) = gossip_once(lctx, &link_client).await {
                tracing::warn!(neigh_label, err = debug(err), "gossip failed",);
            }
        };
        if once.timeout(Duration::from_secs(10)).await.is_none() {
            tracing::warn!("gossip once timed out");
        };
        smol::Timer::after(Duration::from_secs(1)).await;
    }
}

async fn gossip_once(lctx: &LinkContext, link_client: &LinkClient) -> anyhow::Result<()> {
    if lctx.ctx.init().is_client() {
        match &lctx.neighbor {
            Either::Left(_) => {
                fetch_identity(lctx, link_client).await?;
                gossip_graph(lctx, link_client).await?;
            }
            Either::Right(_) => {
                gossip_graph(lctx, link_client).await?;
            }
        };
    } else {
        fetch_identity(lctx, link_client).await?;
        sign_adjacency(lctx, link_client).await?;
        gossip_graph(lctx, link_client).await?;
    }

    Ok(())
}

// Step 1: Fetch the identity of the neighbor.
#[tracing::instrument(skip(lctx, link_client))]
async fn fetch_identity(lctx: &LinkContext, link_client: &LinkClient) -> anyhow::Result<()> {
    let remote_fp = match lctx.neighbor {
        Either::Left(RelayNeighbor(_, fp)) => fp,
        Either::Right(_) => return Ok(()),
    };
    tracing::debug!("fetching identity...");
    let their_id = link_client
        .identity(remote_fp)
        .await?
        .context("they refused to give us their id descriptor")?;
    lctx.ctx
        .get(RELAY_GRAPH)
        .write()
        .insert_identity(their_id)?;
    Ok(())
}

// Step 2: Sign an adjacency descriptor with the neighbor if the local node is "left" of the neighbor.
#[tracing::instrument(skip(lctx, link_client))]
async fn sign_adjacency(lctx: &LinkContext, link_client: &LinkClient) -> anyhow::Result<()> {
    let neighbor_fp = match &lctx.neighbor {
        Either::Left(RelayNeighbor(_, fp)) => fp,
        Either::Right(_) => return Ok(()),
    };
    tracing::debug!("signing adjacency...");
    let my_sk = lctx
        .ctx
        .get(MY_RELAY_IDENTITY)
        .expect("only relays have global identities");
    let my_fingerprint = my_sk.public().fingerprint();
    if my_fingerprint < *neighbor_fp {
        // tracing::debug!("signing adjacency with {remote_fingerprint}");
        let mut left_incomplete = AdjacencyDescriptor {
            left: my_fingerprint,
            right: *neighbor_fp,
            left_sig: Bytes::new(),
            right_sig: Bytes::new(),
            unix_timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        };
        left_incomplete.left_sig = my_sk.sign(left_incomplete.to_sign().as_bytes());
        let complete = link_client
            .sign_adjacency(left_incomplete)
            .await?
            .context("remote refused to sign off")?;
        lctx.ctx
            .get(RELAY_GRAPH)
            .write()
            .insert_adjacency(complete.clone())?;
        // tracing::trace!("inserted the new adjacency {:?} into the graph", complete);
    }
    Ok(())
}

// Step 3: Gossip the relay graph, by asking info about random nodes.
#[tracing::instrument(skip(lctx, link_client))]
async fn gossip_graph(lctx: &LinkContext, link_client: &LinkClient) -> anyhow::Result<()> {
    tracing::debug!("gossipping relay graph...");
    let all_known_nodes = lctx.ctx.get(RELAY_GRAPH).read().all_nodes().collect_vec();
    let random_sample = all_known_nodes
        .choose_multiple(&mut thread_rng(), 10.min(all_known_nodes.len()))
        .copied()
        .collect_vec();
    let adjacencies = link_client.adjacencies(random_sample).await?;
    for adjacency in adjacencies {
        let left_fp = adjacency.left;
        let right_fp = adjacency.right;

        static IDENTITY_CACHE: CtxField<Cache<RelayFingerprint, IdentityDescriptor>> = |_| {
            CacheBuilder::default()
                .time_to_live(Duration::from_secs(60))
                .build()
        };

        let left_id = if let Some(val) = lctx.ctx.get(IDENTITY_CACHE).get(&left_fp) {
            Some(val)
        } else {
            link_client
                .identity(left_fp)
                .await?
                .tap_some(|id| lctx.ctx.get(IDENTITY_CACHE).insert(left_fp, id.clone()))
        };

        let right_id = if let Some(val) = lctx.ctx.get(IDENTITY_CACHE).get(&right_fp) {
            Some(val)
        } else {
            link_client
                .identity(right_fp)
                .await?
                .tap_some(|id| lctx.ctx.get(IDENTITY_CACHE).insert(right_fp, id.clone()))
        };

        // fetch and insert the identities. we unconditionally do this since identity descriptors may change over time
        if let Some(left_id) = left_id {
            lctx.ctx.get(RELAY_GRAPH).write().insert_identity(left_id)?
        }

        if let Some(right_id) = right_id {
            lctx.ctx
                .get(RELAY_GRAPH)
                .write()
                .insert_identity(right_id)?
        }

        // insert the adjacency
        lctx.ctx
            .get(RELAY_GRAPH)
            .write()
            .insert_adjacency(adjacency)?
    }
    Ok(())
}
