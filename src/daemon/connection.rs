use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use concurrent_queue::ConcurrentQueue;
use earendil_packet::{Fingerprint, RawPacket};
use earendil_topology::{AdjacencyDescriptor, IdentityDescriptor, IdentityPublic};
use futures_util::TryFutureExt;
use nanorpc::{JrpcRequest, JrpcResponse, RpcService, RpcTransport};
use smol::{
    channel::{Receiver, Sender},
    future::FutureExt,
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    stream::StreamExt,
    Task,
};
use smolscale::reaper::TaskReaper;
use sosistab2::{Multiplex, MuxSecret, MuxStream, Pipe};
use stdcode::StdcodeSerializeExt;

use super::{
    n2n::{AuthResponse, InfoResponse, N2nClient, N2nProtocol, N2nService},
    DaemonContext,
};

/// Encapsulates a single node-to-node connection (may be relay-relay or client-relay).
#[derive(Clone)]
pub struct Connection {
    mplex: Arc<Multiplex>,
    send_outgoing: Sender<RawPacket>,
    recv_incoming: Receiver<RawPacket>,
    remote_idpk: IdentityPublic,
    _task: Arc<Task<()>>,
}

impl Connection {
    /// Creates a new Connection, from a single Pipe. Unlike in Geph, n2n Multiplexes in earendil all contain one pipe each.
    pub async fn connect(ctx: DaemonContext, pipe: impl Pipe) -> anyhow::Result<Self> {
        // First, we construct the Multiplex.
        let my_mux_sk = MuxSecret::generate();
        let mplex = Arc::new(Multiplex::new(my_mux_sk, None));
        mplex.add_pipe(pipe);
        let (send_outgoing, recv_outgoing) = smol::channel::bounded(1);
        let (send_incoming, recv_incoming) = smol::channel::bounded(1);
        let _task = Arc::new(smolscale::spawn(
            connection_loop(ctx, mplex.clone(), send_incoming, recv_outgoing).unwrap_or_else(|e| {
                log::error!("connection_loop died with {:?}", e);
            }),
        ));
        let rpc = MultiplexRpcTransport::new(mplex.clone());
        let n2n = N2nClient::from(rpc);
        let resp = n2n
            .authenticate()
            .await
            .context("did not respond to authenticate")?;
        if !resp.verify(&mplex.peer_pk().context("could not obtain peer_pk")?) {
            anyhow::bail!("did not authenticate correctly")
        }

        Ok(Self {
            mplex,
            send_outgoing,
            recv_incoming,
            remote_idpk: resp.full_pk,
            _task,
        })
    }

    /// Returns the identity publickey presented by the other side.
    pub fn remote_idpk(&self) -> IdentityPublic {
        self.remote_idpk
    }

    /// Returns a handle to the N2N RPC.
    pub fn n2n_rpc(&self) -> N2nClient {
        N2nClient::from(MultiplexRpcTransport::new(self.mplex.clone()))
    }

    /// Sends an onion-routing packet down this connection.
    pub async fn send_raw_packet(&self, pkt: RawPacket) -> anyhow::Result<()> {
        self.send_outgoing.send(pkt).await?;
        Ok(())
    }

    /// Sends an onion-routing packet down this connection.
    pub async fn recv_raw_packet(&self) -> anyhow::Result<RawPacket> {
        Ok(self.recv_incoming.recv().await?)
    }
}

/// Main loop for the connection.
async fn connection_loop(
    ctx: DaemonContext,
    mplex: Arc<Multiplex>,
    send_incoming: Sender<RawPacket>,
    recv_outgoing: Receiver<RawPacket>,
) -> anyhow::Result<()> {
    let _onion_keepalive = smolscale::spawn(onion_keepalive(
        mplex.clone(),
        send_incoming.clone(),
        recv_outgoing.clone(),
    ));

    let service = Arc::new(N2nService(N2nProtocolImpl {
        ctx: ctx.clone(),
        mplex: mplex.clone(),
    }));

    let group: TaskReaper<anyhow::Result<()>> = TaskReaper::new();
    loop {
        let service = service.clone();
        let mut stream = mplex.accept_conn().await?;

        match stream.additional_info() {
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
) {
    loop {
        let res = async {
            let stream = mplex.open_conn("onion_packets").await?;
            handle_onion_packets(stream, send_incoming.clone(), recv_outgoing.clone()).await
        }
        .await;

        if let Err(e) = res {
            // closed channels are unremarkable
            if !e.to_string().contains("closed channel") {
                log::error!("onion_keepalive failed with error: {:?}", e);
            }
        }
    }
}

async fn handle_onion_packets(
    conn: MuxStream,
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

type PooledConn = (BufReader<MuxStream>, MuxStream);

struct MultiplexRpcTransport {
    mplex: Arc<Multiplex>,
    conn_pool: ConcurrentQueue<(PooledConn, Instant)>,
}

impl MultiplexRpcTransport {
    /// Constructs a Multiplex-backed RpcTransport.
    fn new(mplex: Arc<Multiplex>) -> Self {
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

struct N2nProtocolImpl {
    ctx: DaemonContext,
    mplex: Arc<Multiplex>,
}

#[async_trait]
impl N2nProtocol for N2nProtocolImpl {
    async fn authenticate(&self) -> AuthResponse {
        let local_pk = self.mplex.local_pk();
        AuthResponse::new(&self.ctx.identity, &local_pk)
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
            && left_incomplete.right == self.ctx.identity.public().fingerprint()
            && self.ctx.table.lookup(&left_incomplete.left).is_some();
        if !valid {
            return None;
        }
        // Fill in the right-hand-side
        let signature = self.ctx.identity.sign(left_incomplete.to_sign().as_bytes());
        left_incomplete.right_sig = signature;

        self.ctx
            .relay_graph
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
        self.ctx.relay_graph.read().identity(&fp)
    }

    async fn adjacencies(&self, fp: Fingerprint) -> Vec<AdjacencyDescriptor> {
        self.ctx
            .relay_graph
            .read()
            .adjacencies(&fp)
            .into_iter()
            .flatten()
            .collect()
    }
}
