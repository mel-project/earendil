use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use clone_macro::clone;
use earendil_crypt::{Fingerprint, IdentityPublic, IdentitySecret};
use earendil_packet::{crypt::OnionPublic, Dock};
use futures_util::io;
use moka::sync::{Cache, CacheBuilder};
use serde::{Deserialize, Serialize};
use smol::{
    future::FutureExt,
    io::AsyncReadExt,
    net::{TcpStream, UdpSocket},
};
use smolscale::{immortal::Immortal, reaper::TaskReaper};
use stdcode::StdcodeSerializeExt;

use crate::{
    config::{ForwardHandler, HavenForwardConfig},
    daemon::context::DaemonContext,
    socket::{Endpoint, Socket},
    stream::StreamListener,
    utils::id_from_seed,
};

pub const HAVEN_FORWARD_DOCK: Dock = 100002;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HavenLocator {
    pub identity_pk: IdentityPublic,
    pub onion_pk: OnionPublic,
    pub rendezvous_point: Fingerprint,
    pub signature: Bytes,
}

impl HavenLocator {
    pub fn new(
        identity_sk: IdentitySecret,
        onion_pk: OnionPublic,
        rendezvous_fingerprint: Fingerprint,
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
    pub identity_pk: IdentityPublic,
    pub sig: Bytes,
    pub unix_timestamp: u64,
}

impl RegisterHavenReq {
    pub fn new(identity_sk: IdentitySecret) -> Self {
        let mut reg = Self {
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
        ForwardHandler::UdpForward { from_dock, to_port } => {
            udp_forward(ctx, haven_cfg, from_dock, to_port).await
        }
        ForwardHandler::TcpForward { from_dock, to_port } => {
            tcp_forward(ctx, haven_cfg, from_dock, to_port).await
        }
        ForwardHandler::SimpleProxy { listen_dock } => {
            simple_proxy(ctx, haven_cfg, listen_dock).await
        }
    }
}

async fn udp_forward(
    ctx: DaemonContext,
    haven_cfg: HavenForwardConfig,
    from_dock: Dock,
    to_port: u16,
) -> anyhow::Result<()> {
    // down loop forwards packets back down to the source Earendil endpoints
    async fn down_loop(
        udp_skt: Arc<UdpSocket>,
        earendil_skt: Arc<Socket>,
        earendil_dest: Endpoint,
    ) -> anyhow::Result<()> {
        loop {
            let mut buf = [0; 10_000];
            let (n, _) = udp_skt.recv_from(&mut buf).await?;
            let msg = buf[..n].to_vec();
            earendil_skt.send_to(msg.into(), earendil_dest).await?;
        }
    }

    let haven_id = id_from_seed(&haven_cfg.identity_seed);
    log::debug!(
        "UDP forward haven fingerprint: {}",
        haven_id.public().fingerprint()
    );

    let earendil_skt = Arc::new(Socket::bind_haven_internal(
        ctx.clone(),
        haven_id,
        Some(from_dock),
        Some(haven_cfg.rendezvous),
    ));
    let dmux_table: Cache<Endpoint, (Arc<UdpSocket>, Arc<Immortal>)> = CacheBuilder::default()
        .time_to_idle(Duration::from_secs(60 * 60))
        .build();

    // up loop forwards traffic from destination Earendil endpoint to the destination UDP socket address
    loop {
        let (message, src_endpoint) = earendil_skt.recv_from().await?;
        let udp_socket = if let Some((socket, _)) = dmux_table.get(&src_endpoint) {
            socket
        } else {
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
            let down_task = Immortal::respawn(
                smolscale::immortal::RespawnStrategy::Immediate,
                clone!([earendil_skt, socket], move || {
                    down_loop(socket.clone(), earendil_skt.clone(), src_endpoint)
                }),
            );
            dmux_table.insert(src_endpoint, (socket.clone(), Arc::new(down_task)));

            socket
        };

        udp_socket
            .send_to(&message, format!("127.0.0.1:{to_port}"))
            .await?;
    }
}

async fn tcp_forward(
    ctx: DaemonContext,
    haven_cfg: HavenForwardConfig,
    from_dock: Dock,
    to_port: u16,
) -> anyhow::Result<()> {
    let haven_id = id_from_seed(&haven_cfg.identity_seed);
    log::debug!(
        "TCP forward haven fingerprint: {}",
        haven_id.public().fingerprint()
    );

    let earendil_skt = Socket::bind_haven_internal(
        ctx.clone(),
        haven_id,
        Some(from_dock),
        Some(haven_cfg.rendezvous),
    );

    let mut listener = StreamListener::listen(earendil_skt);

    let reaper = TaskReaper::new();

    loop {
        let earendil_stream = listener.accept().await?;
        let tcp_stream = TcpStream::connect(format!("127.0.0.1:{to_port}")).await?;

        log::debug!("TCP forward earendil stream accepted");
        reaper.attach(smolscale::spawn(async move {
            io::copy(earendil_stream.clone(), &mut tcp_stream.clone())
                .race(io::copy(tcp_stream.clone(), &mut earendil_stream.clone()))
                .await?;
            anyhow::Ok(())
        }));
    }
}

async fn simple_proxy(
    ctx: DaemonContext,
    haven_cfg: HavenForwardConfig,
    listen_dock: u32,
) -> Result<(), anyhow::Error> {
    let haven_id = id_from_seed(&haven_cfg.identity_seed);
    log::debug!(
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

    let reaper = TaskReaper::new();
    loop {
        let mut earendil_stream = listener.accept().await?;

        log::debug!("simple proxy forward earendil stream accepted");
        reaper.attach(smolscale::spawn(async move {
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
        }));
    }
}
