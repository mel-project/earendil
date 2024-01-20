use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use async_trait::async_trait;

use clone_macro::clone;
use concurrent_queue::ConcurrentQueue;
use earendil_crypt::{Fingerprint, IdentityPublic};
use earendil_packet::RawPacket;
use earendil_topology::{AdjacencyDescriptor, IdentityDescriptor};
use futures_util::AsyncWriteExt;
use itertools::Itertools;
use nanorpc::{JrpcRequest, JrpcResponse, RpcService, RpcTransport};
use once_cell::sync::OnceCell;

use rand::Rng;
use smol::{
    channel::Receiver,
    future::FutureExt,
    io::{AsyncBufReadExt, BufReader},
    stream::StreamExt,
};

use smol_timeout::TimeoutExt;
use smolscale::immortal::{Immortal, RespawnStrategy};
use sosistab2::Multiplex;

use crate::daemon::{
    context::{DEBTS, GLOBAL_IDENTITY, NEIGH_TABLE_NEW, RELAY_GRAPH, SETTLEMENTS},
    peel_forward::peel_forward,
    settlement::{Seed, SettlementProof, SettlementRequest, SettlementResponse},
};

use super::{
    chat::incoming_chat,
    link_protocol::{AuthResponse, InfoResponse, LinkClient, LinkProtocol, LinkService},
    DaemonContext,
};

/// Authenticates the other side of the link, from a single Pipe. Unlike in Geph, n2n Multiplexes in earendil all contain one pipe each.
pub async fn link_authenticate(
    mplex: Arc<Multiplex>,
    their_fp: Option<Fingerprint>,
) -> anyhow::Result<IdentityPublic> {
    let rpc = LinkRpcTransport::new(mplex.clone());
    let client = LinkClient::from(rpc);

    let resp = client
        .authenticate()
        .await
        .context("did not respond to authenticate")?;

    resp.verify(&mplex.peer_pk().context("could not obtain peer_pk")?)
        .context("did not authenticate correctly")?;
    if let Some(their_fp) = their_fp {
        if their_fp != resp.full_pk.fingerprint() {
            anyhow::bail!(
                "neighbor fingerprint {} different from configured {}",
                resp.full_pk.fingerprint(),
                their_fp
            )
        }
    }
    Ok(resp.full_pk)
}

/// Main loop for the connection.
#[tracing::instrument(skip(service, mplex, recv_outgoing))]
pub async fn connection_loop(
    service: Arc<LinkService<LinkProtocolImpl>>,
    mplex: Arc<Multiplex>,
    recv_outgoing: Receiver<RawPacket>,
) -> anyhow::Result<()> {
    let _onion_keepalive = Immortal::respawn(
        RespawnStrategy::Immediate,
        clone!([mplex, recv_outgoing, service], move || {
            onion_keepalive(service.clone(), mplex.clone(), recv_outgoing.clone())
        }),
    );

    let group = smol::Executor::new();
    group
        .run(async {
            loop {
                let service = service.clone();
                let mut stream = mplex.accept_conn().await?;

                match stream.label() {
                    "n2n_control" => group
                        .spawn(async move {
                            let mut stream_lines = BufReader::new(stream.clone()).lines();
                            while let Some(line) = stream_lines.next().await {
                                let line = line?;
                                let req: JrpcRequest = serde_json::from_str(&line)?;
                                // tracing::debug!(method = req.method, "LinkRPC request received");
                                let resp = service.respond_raw(req).await;
                                stream
                                    .write_all((serde_json::to_string(&resp)? + "\n").as_bytes())
                                    .await?;
                            }
                            anyhow::Ok(())
                        })
                        .detach(),
                    "onion_packets" => group
                        .spawn(handle_onion_packets(
                            service.clone(),
                            stream,
                            recv_outgoing.clone(),
                        ))
                        .detach(),
                    other => {
                        log::error!("could not handle {other}");
                    }
                }
            }
        })
        .await
}

#[tracing::instrument(skip(service, mplex, recv_outgoing))]
async fn onion_keepalive(
    service: Arc<LinkService<LinkProtocolImpl>>,
    mplex: Arc<Multiplex>,
    recv_outgoing: Receiver<RawPacket>,
) -> anyhow::Result<()> {
    loop {
        let stream = mplex.open_conn("onion_packets").await?;
        handle_onion_packets(service.clone(), stream, recv_outgoing.clone()).await?;
    }
}

#[tracing::instrument(skip(service, conn, recv_outgoing))]
async fn handle_onion_packets(
    service: Arc<LinkService<LinkProtocolImpl>>,
    conn: sosistab2::Stream,
    recv_outgoing: Receiver<RawPacket>,
) -> anyhow::Result<()> {
    let up = async {
        loop {
            let pkt = recv_outgoing.recv().await?;
            conn.send_urel(bytemuck::bytes_of(&pkt).to_vec().into())
                .await?;
        }
    };
    let dn = async {
        loop {
            let pkt = conn.recv_urel().await?;
            let pkt: RawPacket = *bytemuck::try_from_bytes(&pkt)
                .ok()
                .context("incoming urel packet of the wrong size to be an onion packet")?;
            if let Some(other_fp) = service.0.remote_pk.get() {
                peel_forward(&service.0.ctx, other_fp.fingerprint(), pkt);
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
        let stream = self.mplex.open_conn("n2n_control").await?;
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
    pub remote_pk: Arc<OnceCell<IdentityPublic>>,
    pub max_outgoing_price: u64,
}

#[async_trait]
impl LinkProtocol for LinkProtocolImpl {
    async fn authenticate(&self) -> AuthResponse {
        let local_pk = self.mplex.local_pk();
        AuthResponse::new(self.ctx.get(GLOBAL_IDENTITY), &local_pk)
    }

    async fn info(&self) -> InfoResponse {
        InfoResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    async fn sign_adjacency(
        &self,
        mut left_incomplete: AdjacencyDescriptor,
    ) -> Option<AdjacencyDescriptor> {
        // This must be a neighbor that is "left" of us
        let valid = left_incomplete.left < left_incomplete.right
            && left_incomplete.right == self.ctx.get(GLOBAL_IDENTITY).public().fingerprint()
            && self
                .ctx
                .get(NEIGH_TABLE_NEW)
                .get(&left_incomplete.left)
                .is_some();
        if !valid {
            log::debug!("neighbor not right of us! Refusing to sign adjacency x_x");
            return None;
        }
        // Fill in the right-hand-side
        let signature = self
            .ctx
            .get(GLOBAL_IDENTITY)
            .sign(left_incomplete.to_sign().as_bytes());
        left_incomplete.right_sig = signature;

        self.ctx
            .get(RELAY_GRAPH)
            .write()
            .insert_adjacency(left_incomplete.clone())
            .map_err(|e| {
                log::warn!("could not insert here: {:?}", e);
                e
            })
            .ok()?;
        Some(left_incomplete)
    }

    async fn identity(&self, fp: Fingerprint) -> Option<IdentityDescriptor> {
        self.ctx.get(RELAY_GRAPH).read().identity(&fp)
    }

    async fn adjacencies(&self, fps: Vec<Fingerprint>) -> Vec<AdjacencyDescriptor> {
        let rg = self.ctx.get(RELAY_GRAPH).read();
        fps.into_iter()
            .flat_map(|fp| {
                rg.adjacencies(&fp).into_iter().flatten().filter(|adj| {
                    rg.identity(&adj.left).map_or(false, |id| id.is_relay)
                        && rg.identity(&adj.right).map_or(false, |id| id.is_relay)
                })
            })
            .dedup()
            .collect()
    }

    async fn push_price(&self, price: u64, debt_limit: u64) {
        log::trace!("received push price");
        let remote_fp = match self.remote_pk.get() {
            Some(rpk) => rpk.fingerprint(),
            None => {
                return;
            }
        };

        if price > self.max_outgoing_price {
            log::warn!("neigh {} price too high! YOU SHOULD MANUALLY REMOVE THIS NEIGHBOR UNTIL YOU RESOLVE THE ISSUE", remote_fp);
        } else {
            self.ctx
                .get(DEBTS)
                .insert_outgoing_price(remote_fp, price, debt_limit);
            log::trace!("Successfully registered {} price!", remote_fp);
        }
    }

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

    async fn push_chat(&self, msg: String) {
        if let Some(neighbor) = self.remote_pk.get() {
            log::debug!("pushing chat: {}", msg.clone());
            incoming_chat(&self.ctx, neighbor.fingerprint(), msg);
        }
    }

    async fn request_seed(&self) -> Option<Seed> {
        let seed = rand::thread_rng().gen();
        let seed_cache = &self.ctx.get(SETTLEMENTS).seed_cache;

        if let Some(pk) = self.remote_pk.get() {
            let fp = pk.fingerprint();
            match seed_cache.get(&fp) {
                Some(mut seeds) => {
                    seeds.insert(seed);
                    seed_cache.insert(fp, seeds);
                    return Some(seed);
                }
                None => {
                    let mut seed_set = HashSet::new();
                    seed_set.insert(seed);
                    seed_cache.insert(fp, seed_set);
                    return Some(seed);
                }
            }
        }

        None
    }
}
