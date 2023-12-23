use std::{
    convert::Infallible,
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
use futures_util::{AsyncWriteExt, TryFutureExt};
use itertools::Itertools;
use nanorpc::{JrpcRequest, JrpcResponse, RpcService, RpcTransport};
use parking_lot::Mutex;
use smol::{
    channel::{Receiver, Sender},
    future::FutureExt,
    io::{AsyncBufReadExt, BufReader},
    stream::StreamExt,
    Task,
};
use smolscale::{
    immortal::{Immortal, RespawnStrategy},
    reaper::TaskReaper,
};
use sosistab2::{Multiplex, MuxSecret, Pipe};

use super::{
    context::{DEBTS, GLOBAL_IDENTITY, NEIGH_TABLE, RELAY_GRAPH},
    link_protocol::{AuthResponse, InfoResponse, LinkClient, LinkProtocol, LinkService},
    DaemonContext,
};

/// Encapsulates a single node-to-node connection (may be relay-relay or client-relay).
#[derive(Clone)]
pub struct LinkConnection {
    send_outgoing: Sender<RawPacket>,
    recv_incoming: Receiver<RawPacket>,
    remote_idpk: IdentityPublic,
}

pub struct LinkInfo {
    pub conn: LinkConnection,
    pub client: LinkClient,
    pub task: Task<Infallible>,
}

impl LinkConnection {
    /// Creates a new Connection, from a single Pipe. Unlike in Geph, n2n Multiplexes in earendil all contain one pipe each.
    pub async fn connect(
        ctx: DaemonContext,
        pipe: impl Pipe,
        max_outgoing_price: u64,
    ) -> anyhow::Result<LinkInfo> {
        let my_mux_sk = MuxSecret::generate();
        let mplex = Arc::new(Multiplex::new(my_mux_sk, None));
        mplex.add_pipe(pipe);
        let (send_outgoing, recv_outgoing) = smol::channel::bounded(1);
        let (send_incoming, recv_incoming) = smol::channel::bounded(1);
        let rpc = MultiplexRpcTransport::new(mplex.clone());
        let client = LinkClient::from(rpc);

        let remote_pk_shared = Arc::new(Mutex::new(None));

        let service = Arc::new(LinkService(LinkProtocolImpl {
            ctx: ctx.clone(),
            mplex: mplex.clone(),
            remote_pk: remote_pk_shared.clone(),
            max_outgoing_price,
        }));

        let task = smolscale::spawn(
            connection_loop(mplex.clone(), send_incoming, recv_outgoing, service)
                .unwrap_or_else(|e| panic!("connection_loop died with {:?}", e)),
        );

        let resp = client
            .authenticate()
            .await
            .context("did not respond to authenticate")?;

        resp.verify(&mplex.peer_pk().context("could not obtain peer_pk")?)
            .context("did not authenticated correctly")?;

        let mut remote_pk = remote_pk_shared.lock();
        *remote_pk = Some(resp.full_pk);

        let conn = Self {
            send_outgoing,
            recv_incoming,
            remote_idpk: resp.full_pk,
        };

        Ok(LinkInfo { conn, client, task })
    }

    /// Returns the identity publickey presented by the other side.
    pub fn remote_idpk(&self) -> IdentityPublic {
        self.remote_idpk
    }

    /// Sends an onion-routing packet down this connection.
    pub async fn send_raw_packet(&self, pkt: RawPacket) {
        self.send_outgoing.send(pkt).await.unwrap();
    }

    /// Sends an onion-routing packet down this connection.
    pub async fn recv_raw_packet(&self) -> RawPacket {
        self.recv_incoming.recv().await.unwrap()
    }
}

/// Main loop for the connection.
pub async fn connection_loop(
    mplex: Arc<Multiplex>,
    send_incoming: Sender<RawPacket>,
    recv_outgoing: Receiver<RawPacket>,
    service: Arc<LinkService<LinkProtocolImpl>>,
) -> anyhow::Result<Infallible> {
    let _onion_keepalive = Immortal::respawn(
        RespawnStrategy::Immediate,
        clone!([mplex, send_incoming, recv_outgoing], move || {
            onion_keepalive(mplex.clone(), send_incoming.clone(), recv_outgoing.clone())
        }),
    );

    let group: TaskReaper<anyhow::Result<()>> = TaskReaper::new();
    loop {
        let service = service.clone();
        let mut stream = mplex.accept_conn().await?;

        match stream.label() {
            "n2n_control" => group.attach(smolscale::spawn(async move {
                let mut stream_lines = BufReader::new(stream.clone()).lines();
                while let Some(line) = stream_lines.next().await {
                    let line = line?;
                    let req: JrpcRequest = serde_json::from_str(&line)?;
                    let resp = service.respond_raw(req).await;
                    stream
                        .write_all((serde_json::to_string(&resp)? + "\n").as_bytes())
                        .await?;
                }
                Ok(())
            })),
            "onion_packets" => group.attach(smolscale::spawn(handle_onion_packets(
                stream,
                send_incoming.clone(),
                recv_outgoing.clone(),
            ))),
            other => {
                log::error!("could not handle {other}");
            }
        }
    }
}

async fn onion_keepalive(
    mplex: Arc<Multiplex>,
    send_incoming: Sender<RawPacket>,
    recv_outgoing: Receiver<RawPacket>,
) -> anyhow::Result<()> {
    loop {
        let stream = mplex.open_conn("onion_packets").await?;
        handle_onion_packets(stream, send_incoming.clone(), recv_outgoing.clone()).await?;
    }
}

async fn handle_onion_packets(
    conn: sosistab2::Stream,
    send_incoming: Sender<RawPacket>,
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
            send_incoming.send(pkt).await?;
        }
    };
    up.race(dn).await
}

const POOL_TIMEOUT: Duration = Duration::from_secs(60);

type PooledConn = (BufReader<sosistab2::Stream>, sosistab2::Stream);

pub struct MultiplexRpcTransport {
    mplex: Arc<Multiplex>,
    conn_pool: ConcurrentQueue<(PooledConn, Instant)>,
}

impl MultiplexRpcTransport {
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
impl RpcTransport for MultiplexRpcTransport {
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
    pub remote_pk: Arc<Mutex<Option<IdentityPublic>>>,
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
                .get(NEIGH_TABLE)
                .lookup(&left_incomplete.left)
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
        log::debug!("received push price");
        let remote_fp = match *self.remote_pk.lock() {
            Some(rpk) => rpk.fingerprint(),
            None => {
                return;
            }
        };

        if price > self.max_outgoing_price {
            log::warn!("neigh {} price too high!", remote_fp);
            self.ctx.get(NEIGH_TABLE).remove(&remote_fp);
        } else {
            self.ctx
                .get(DEBTS)
                .insert_outgoing_price(remote_fp, price, debt_limit);
            log::debug!("Successfully registered {} price!", remote_fp);
        }
    }
}
