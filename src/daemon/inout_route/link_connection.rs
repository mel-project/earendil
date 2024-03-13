use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use async_trait::async_trait;

use bytemuck::{Pod, Zeroable};
use clone_macro::clone;
use concurrent_queue::ConcurrentQueue;
use earendil_crypt::{ClientId, NodeId, RelayFingerprint, RelayIdentityPublic};
use earendil_packet::{RawBody, RawPacket};
use earendil_topology::{AdjacencyDescriptor, IdentityDescriptor};
use futures_util::AsyncWriteExt;
use itertools::Itertools;
use nanorpc::{JrpcRequest, JrpcResponse, RpcService, RpcTransport};
use nursery_macro::nursery;

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

use crate::context::{
    DaemonContext, DEBTS, DEGARBLERS, GLOBAL_IDENTITY, NEIGH_TABLE_NEW, RELAY_GRAPH, SETTLEMENTS,
};
use crate::daemon::{
    inout_route::chat::{incoming_client_chat, incoming_relay_chat},
    peel_forward::{client_process_inner_pkt, peel_forward, relay_one_hop_closer},
    rrb_balance::decrement_rrb_balance,
};
use crate::settlement::{Seed, SettlementProof, SettlementRequest, SettlementResponse};

use super::link_protocol::{InfoResponse, LinkProtocol, LinkService};

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

/// Manages connections for clients.
#[tracing::instrument(skip(service, mplex, recv_outgoing))]
pub async fn client_relay_connection_loop(
    service: Arc<LinkService<LinkProtocolImpl>>,
    mplex: Arc<Multiplex>,
    recv_outgoing: Receiver<(RawPacket, RelayFingerprint)>,
) -> anyhow::Result<()> {
    let _onion_keepalive = Immortal::respawn(
        RespawnStrategy::Immediate,
        clone!([mplex, recv_outgoing, service], move || {
            client_relay_onion_keepalive(service.clone(), mplex.clone(), recv_outgoing.clone())
        }),
    );

    nursery!({
        loop {
            let service = service.clone();
            let mut stream = mplex.accept_conn().await?;

            match stream.label() {
                "n2n_control" => spawn!(async move {
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
                "onion_packets" => spawn!(relay_handle_onion(
                    service.clone(),
                    stream,
                    recv_outgoing.clone(),
                ))
                .detach(),
                other => {
                    tracing::error!("could not handle {other}");
                }
            }
        }
    })
}

/// Manages connections for relay connected to other relays.
#[tracing::instrument(skip(service, mplex, recv_outgoing))]
pub async fn relay_connection_loop(
    service: Arc<LinkService<LinkProtocolImpl>>,
    mplex: Arc<Multiplex>,
    recv_outgoing: Receiver<(RawPacket, RelayFingerprint)>,
) -> anyhow::Result<()> {
    let _onion_keepalive = Immortal::respawn(
        RespawnStrategy::Immediate,
        clone!([mplex, recv_outgoing, service], move || {
            relay_onion_keepalive(service.clone(), mplex.clone(), recv_outgoing.clone())
        }),
    );

    nursery!({
        loop {
            let service = service.clone();
            let mut stream = mplex.accept_conn().await?;

            match stream.label() {
                "n2n_control" => spawn!(async move {
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
                "onion_packets" => spawn!(relay_handle_onion(
                    service.clone(),
                    stream,
                    recv_outgoing.clone(),
                ))
                .detach(),
                other => {
                    tracing::error!("could not handle {other}");
                }
            }
        }
    })
}

/// Manages connections for clients.
#[tracing::instrument(skip(service, mplex, recv_outgoing))]
pub async fn relay_client_connection_loop(
    service: Arc<LinkService<LinkProtocolImpl>>,
    mplex: Arc<Multiplex>,
    recv_outgoing: Receiver<(RawBody, u64)>,
) -> anyhow::Result<()> {
    let _onion_keepalive = Immortal::respawn(
        RespawnStrategy::Immediate,
        clone!([mplex, recv_outgoing, service], move || {
            relay_client_onion_keepalive(service.clone(), mplex.clone(), recv_outgoing.clone())
        }),
    );

    nursery!({
        loop {
            let service = service.clone();
            let mut stream = mplex.accept_conn().await?;

            match stream.label() {
                "n2n_control" => spawn!(async move {
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
                "onion_packets" => spawn!(relay_client_handle_onion(
                    service.clone(),
                    stream,
                    recv_outgoing.clone(),
                ))
                .detach(),
                other => {
                    tracing::error!("could not handle {other}");
                }
            }
        }
    })
}

#[tracing::instrument(skip(service, mplex, recv_outgoing))]
async fn client_relay_onion_keepalive(
    service: Arc<LinkService<LinkProtocolImpl>>,
    mplex: Arc<Multiplex>,
    recv_outgoing: Receiver<(RawPacket, RelayFingerprint)>,
) -> anyhow::Result<()> {
    loop {
        let stream = mplex.open_conn("onion_packets").await?;
        client_relay_handle_onion(service.clone(), stream, recv_outgoing.clone()).await?;
    }
}

#[tracing::instrument(skip(service, mplex, recv_outgoing))]
async fn relay_onion_keepalive(
    service: Arc<LinkService<LinkProtocolImpl>>,
    mplex: Arc<Multiplex>,
    recv_outgoing: Receiver<(RawPacket, RelayFingerprint)>,
) -> anyhow::Result<()> {
    loop {
        let stream = mplex.open_conn("onion_packets").await?;
        relay_handle_onion(service.clone(), stream, recv_outgoing.clone()).await?;
    }
}

#[tracing::instrument(skip(service, mplex, recv_outgoing))]
async fn relay_client_onion_keepalive(
    service: Arc<LinkService<LinkProtocolImpl>>,
    mplex: Arc<Multiplex>,
    recv_outgoing: Receiver<(RawBody, u64)>,
) -> anyhow::Result<()> {
    loop {
        let stream = mplex.open_conn("onion_packets").await?;
        relay_client_handle_onion(service.clone(), stream, recv_outgoing.clone()).await?;
    }
}

#[tracing::instrument(skip(service, conn, recv_outgoing))]
async fn client_relay_handle_onion(
    service: Arc<LinkService<LinkProtocolImpl>>,
    conn: sosistab2::Stream,
    recv_outgoing: Receiver<(RawPacket, RelayFingerprint)>,
) -> anyhow::Result<()> {
    let up = async {
        loop {
            let (pkt, peeler) = recv_outgoing.recv().await?;
            let pkt_with_peeler = PacketWithPeeler { pkt, peeler };
            conn.send_urel(bytemuck::bytes_of(&pkt_with_peeler).to_vec().into())
                .await?;
        }
    };
    let dn = async {
        loop {
            let pkt = conn.recv_urel().await?;
            let RawBodyWithRbId { mut body, rb_id } = *bytemuck::try_from_bytes(&pkt)
                .ok()
                .context("incoming urel packet of the wrong size to be an onion packet")?;

            let reply_degarbler = service
                .0
                .ctx
                .get(DEGARBLERS)
                .remove(&rb_id)
                .context(format!("no degarbler for pkt with id {rb_id}"))?
                .1;
            let (inner, src_fp) = reply_degarbler.degarble(&mut body)?;

            tracing::debug!("packet has been degarbled!");

            decrement_rrb_balance(&service.0.ctx, reply_degarbler.my_anon_id(), src_fp);
            replenish_rrb(&service.0.ctx, reply_degarbler.my_anon_id(), src_fp)?;

            client_process_inner_pkt(&service.0.ctx, inner, src_fp, reply_degarbler.my_anon_id())?;
        }
    };
    up.race(dn).await
}

#[tracing::instrument(skip(service, conn, recv_outgoing))]
async fn relay_handle_onion(
    service: Arc<LinkService<LinkProtocolImpl>>,
    conn: sosistab2::Stream,
    recv_outgoing: Receiver<(RawPacket, RelayFingerprint)>,
) -> anyhow::Result<()> {
    let up = async {
        loop {
            let (pkt, peeler) = recv_outgoing.recv().await?;
            let pkt_with_peeler = PacketWithPeeler { pkt, peeler };
            conn.send_urel(bytemuck::bytes_of(&pkt_with_peeler).to_vec().into())
                .await?;
        }
    };
    let dn = async {
        loop {
            let pkt = conn.recv_urel().await?;
            let PacketWithPeeler { pkt, peeler } = *bytemuck::try_from_bytes(&pkt)
                .ok()
                .context("incoming urel packet of the wrong size to be an onion packet")?;
            let my_fp = service
                .0
                .ctx
                .get(GLOBAL_IDENTITY)
                .expect("only relays have global identities")
                .public()
                .fingerprint();

            if peeler == my_fp {
                if let Some(pk) = service.0.remote_relay_pk {
                    peel_forward(&service.0.ctx, NodeId::Relay(pk.fingerprint()), peeler, pkt)
                        .await;
                } else {
                    anyhow::bail!("no fingerprint found for link")
                }
            } else if let Some(next_hop) = relay_one_hop_closer(&service.0.ctx, peeler) {
                let conn = service
                    .0
                    .ctx
                    .get(NEIGH_TABLE_NEW)
                    .get(&next_hop)
                    .context(format!("could not find this next hop {next_hop}"))?;

                let _ = conn.try_send((pkt, peeler));
                service.0.ctx.get(DEBTS).incr_relay_outgoing(next_hop);
            } else {
                tracing::warn!("no route found to next peeler {peeler}");
            }
        }
    };
    up.race(dn).await
}

#[tracing::instrument(skip(service, conn, recv_outgoing))]
async fn relay_client_handle_onion(
    service: Arc<LinkService<LinkProtocolImpl>>,
    conn: sosistab2::Stream,
    recv_outgoing: Receiver<(RawBody, u64)>,
) -> anyhow::Result<()> {
    let up = async {
        loop {
            let (body, rb_id) = recv_outgoing.recv().await?;
            let raw_body_with_rb_id = RawBodyWithRbId { body, rb_id };
            conn.send_urel(bytemuck::bytes_of(&raw_body_with_rb_id).to_vec().into())
                .await?;
        }
    };
    let dn = async {
        loop {
            let pkt = conn.recv_urel().await?;
            let PacketWithPeeler { pkt, peeler } = *bytemuck::try_from_bytes(&pkt)
                .ok()
                .context("incoming urel packet of the wrong size to be an onion packet")?;
            let my_fp = service
                .0
                .ctx
                .get(GLOBAL_IDENTITY)
                .expect("only relays have global identities")
                .public()
                .fingerprint();

            if peeler == my_fp {
                if let Some(id) = service.0.remote_client_id {
                    peel_forward(&service.0.ctx, NodeId::Client(id), peeler, pkt).await;
                } else {
                    anyhow::bail!("no client id found for link")
                }
            } else if let Some(next_hop) = relay_one_hop_closer(&service.0.ctx, peeler) {
                let conn = service
                    .0
                    .ctx
                    .get(NEIGH_TABLE_NEW)
                    .get(&next_hop)
                    .context(format!("could not find this next hop {next_hop}"))?;

                let _ = conn.try_send((pkt, peeler));
                service.0.ctx.get(DEBTS).incr_relay_outgoing(next_hop);
            } else {
                tracing::warn!("no route found to next peeler {peeler}");
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
    pub remote_client_id: Option<ClientId>,
    pub remote_relay_pk: Option<RelayIdentityPublic>,
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
            .get(GLOBAL_IDENTITY)
            .expect("only relays have global identities");
        let my_fp = my_sk.public().fingerprint();
        // This must be a neighbor that is "left" of us
        let valid = left_incomplete.left < left_incomplete.right
            && left_incomplete.right == my_fp
            && self
                .ctx
                .get(NEIGH_TABLE_NEW)
                .get(&left_incomplete.left)
                .is_some();
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
    async fn client_push_price(&self, price: u64, debt_limit: u64) {
        tracing::trace!("received push price");
        let remote_client_id = self.remote_client_id.unwrap();
        if price > self.max_outgoing_price {
            tracing::warn!("neigh {} price too high! YOU SHOULD MANUALLY REMOVE THIS NEIGHBOR UNTIL YOU RESOLVE THE ISSUE", remote_client_id);
            self.ctx
                .get(DEBTS)
                .insert_client_outgoing_price(remote_client_id, price, debt_limit);
            tracing::trace!("Successfully registered {} price!", remote_client_id);
        }
    }

    #[tracing::instrument(skip(self))]
    async fn relay_push_price(&self, price: u64, debt_limit: u64) {
        tracing::trace!("received push price");
        let remote_fp = self.remote_relay_pk.unwrap().fingerprint();
        if price > self.max_outgoing_price {
            tracing::warn!("neigh {} price too high! YOU SHOULD MANUALLY REMOVE THIS NEIGHBOR UNTIL YOU RESOLVE THE ISSUE", remote_fp);
            self.ctx
                .get(DEBTS)
                .insert_relay_outgoing_price(remote_fp, price, debt_limit);
            tracing::trace!("Successfully registered {} price!", remote_fp);
        }
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
    async fn push_chat_client(&self, msg: String) {
        log::debug!("pushing chat: {}", msg.clone());
        incoming_client_chat(&self.ctx, self.remote_client_id.unwrap(), msg);
    }

    #[tracing::instrument(skip(self))]
    async fn push_chat_relay(&self, msg: String) {
        log::debug!("pushing chat: {}", msg.clone());
        incoming_relay_chat(&self.ctx, self.remote_relay_pk.unwrap().fingerprint(), msg);
    }

    #[tracing::instrument(skip(self))]
    async fn request_seed(&self) -> Seed {
        let seed = rand::thread_rng().gen();
        let seed_cache = &self.ctx.get(SETTLEMENTS).seed_cache;
        let remote_fp = self
            .remote_relay_pk
            .expect("you cannot ask a client for a seed")
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
