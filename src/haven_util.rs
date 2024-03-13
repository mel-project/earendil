use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use clone_macro::clone;
use earendil_crypt::{AnonRemote, HavenIdentityPublic, HavenIdentitySecret, RelayFingerprint};
use earendil_packet::{crypt::OnionPublic, Dock};
use futures_util::io;
use moka::sync::{Cache, CacheBuilder};
use nursery_macro::nursery;
use serde::{Deserialize, Serialize};
use smol::{
    future::FutureExt,
    io::AsyncReadExt,
    net::{TcpStream, UdpSocket},
};
use smolscale::immortal::Immortal;
use stdcode::StdcodeSerializeExt;

use crate::{
    config::{ForwardHandler, HavenForwardConfig},
    context::DaemonContext,
    socket::{Endpoint, RelayEndpoint, Socket},
    stream::StreamListener,
};

pub const HAVEN_FORWARD_DOCK: Dock = 100002;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HavenLocator {
    pub identity_pk: HavenIdentityPublic,
    pub onion_pk: OnionPublic,
    pub rendezvous_point: RelayFingerprint,
    pub signature: Bytes,
}

impl HavenLocator {
    pub fn new(
        identity_sk: HavenIdentitySecret,
        onion_pk: OnionPublic,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterHavenReq {
    pub anon_id: AnonRemote,
    pub identity_pk: HavenIdentityPublic,
    pub sig: Bytes,
    pub unix_timestamp: u64,
}

impl RegisterHavenReq {
    pub fn new(my_anon_id: AnonRemote, identity_sk: HavenIdentitySecret) -> Self {
        let mut reg = Self {
            anon_id: my_anon_id,
            identity_pk: identity_sk.public(),
            sig: Bytes::new(),
            unix_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        reg.sig = identity_sk.sign(reg.to_sign().as_bytes());
        reg
    }

    pub fn to_sign(&self) -> blake3::Hash {
        let mut this = self.clone();
        this.sig = Bytes::new();
        blake3::keyed_hash(b"haven_registration______________", &this.stdcode())
    }
}

/// Handles incoming earendil traffic to the "server-side".
///
/// Earendil packets are forwarded to their destination  UDP sockets.
///
/// Starts a "down" loop that listens for incoming UDP traffic in the reverse direction and
/// forwards it back to the earnedil network.
pub async fn haven_loop(ctx: DaemonContext, haven_cfg: HavenForwardConfig) -> anyhow::Result<()> {
    match haven_cfg.handler {
        ForwardHandler::UdpService {
            listen_dock,
            upstream,
        } => udp_forward(ctx, haven_cfg, listen_dock, upstream).await,
        ForwardHandler::TcpService {
            listen_dock,
            upstream,
        } => tcp_forward(ctx, haven_cfg, listen_dock, upstream).await,
        ForwardHandler::SimpleProxy { listen_dock } => {
            simple_proxy(ctx, haven_cfg, listen_dock).await
        }
    }
}

#[tracing::instrument(skip(ctx))]
async fn udp_forward(
    ctx: DaemonContext,
    haven_cfg: HavenForwardConfig,
    listen_dock: Dock,
    upstream: SocketAddr,
) -> anyhow::Result<()> {
    // down loop forwards packets back down to the source Earendil endpoints
    async fn down_loop(
        udp_skt: Arc<UdpSocket>,
        earendil_skt: Arc<Socket>,
        earendil_dest: RelayEndpoint,
    ) -> anyhow::Result<()> {
        loop {
            let mut buf = [0; 10_000];
            let (n, _) = udp_skt.recv_from(&mut buf).await?;
            let msg = buf[..n].to_vec();
            earendil_skt
                .send_to(msg.into(), Endpoint::Relay(earendil_dest))
                .await?;
        }
    }

    let haven_id = haven_cfg.identity.actualize_haven()?;
    tracing::debug!(
        "UDP forward haven fingerprint: {}",
        haven_id.public().fingerprint()
    );

    let earendil_skt = Arc::new(Socket::bind_haven_internal(
        ctx.clone(),
        haven_id,
        Some(listen_dock),
        Some(haven_cfg.rendezvous),
    ));
    let dmux_table: Cache<RelayEndpoint, (Arc<UdpSocket>, Arc<Immortal>)> = CacheBuilder::default()
        .time_to_idle(Duration::from_secs(60 * 60))
        .build();

    // up loop forwards traffic from destination Earendil endpoint to the destination UDP socket address
    loop {
        let (message, src_endpoint) = earendil_skt.recv_from().await?;
        if let Endpoint::Relay(src_ep) = src_endpoint {
            let udp_socket = if let Some((socket, _)) = dmux_table.get(&src_ep) {
                socket
            } else {
                let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
                let down_task = Immortal::respawn(
                    smolscale::immortal::RespawnStrategy::Immediate,
                    clone!([earendil_skt, socket], move || {
                        down_loop(socket.clone(), earendil_skt.clone(), src_ep)
                    }),
                );
                dmux_table.insert(src_ep, (socket.clone(), Arc::new(down_task)));

                socket
            };

            udp_socket.send_to(&message, upstream).await?;
        }
    }
}

async fn tcp_forward(
    ctx: DaemonContext,
    haven_cfg: HavenForwardConfig,
    listen_dock: Dock,
    upstream: SocketAddr,
) -> anyhow::Result<()> {
    let haven_id = haven_cfg.identity.actualize_haven()?;
    tracing::debug!(
        "TCP forward haven fingerprint: {}",
        haven_id.public().fingerprint()
    );

    let earendil_skt = Socket::bind_haven_internal(
        ctx.clone(),
        haven_id,
        Some(listen_dock),
        Some(haven_cfg.rendezvous),
    );

    let mut listener = StreamListener::listen(earendil_skt);

    nursery!(loop {
        let earendil_stream = listener.accept().await?;
        let tcp_stream = TcpStream::connect(upstream).await?;
        tracing::trace!("TCP forward earendil stream accepted");
        spawn!(async move {
            io::copy(earendil_stream.clone(), &mut tcp_stream.clone())
                .race(io::copy(tcp_stream.clone(), &mut earendil_stream.clone()))
                .await?;
            anyhow::Ok(())
        })
        .detach();
    })
}

#[tracing::instrument(skip(ctx))]
async fn simple_proxy(
    ctx: DaemonContext,
    haven_cfg: HavenForwardConfig,
    listen_dock: u32,
) -> Result<(), anyhow::Error> {
    let haven_id = haven_cfg.identity.actualize_haven()?;
    tracing::debug!(
        "simple proxy haven fingerprint: {}",
        haven_id.public().fingerprint()
    );

    let earendil_skt = Socket::bind_haven_internal(
        ctx.clone(),
        haven_id,
        Some(listen_dock),
        Some(haven_cfg.rendezvous),
    );

    let mut listener = StreamListener::listen(earendil_skt);

    nursery!(loop {
        let mut earendil_stream = listener.accept().await?;

        tracing::trace!("simple proxy forward earendil stream accepted");
        spawn!(async move {
            // the first 2 bytes of the stream encode the byte-length of the subsequent `hostname:port`
            let mut len_buf = [0; 2];
            earendil_stream.read_exact(&mut len_buf).await?;
            let len: u16 = u16::from_be_bytes(len_buf);

            let mut addr_buf = vec![0; len as usize];
            earendil_stream.read_exact(&mut addr_buf).await?;

            let addr = String::from_utf8_lossy(&addr_buf).into_owned();
            let tcp_stream = TcpStream::connect(addr).await?;

            io::copy(earendil_stream.clone(), &mut tcp_stream.clone())
                .race(io::copy(tcp_stream.clone(), &mut earendil_stream.clone()))
                .await?;
            anyhow::Ok(())
        })
        .detach();
    })
}
