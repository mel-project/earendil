use std::{
    net::{SocketAddr, SocketAddrV4},
    sync::Arc,
};

use clone_macro::clone;
use earendil_crypt::IdentitySecret;
use moka::sync::Cache;
use smol::net::UdpSocket;
use smolscale::immortal::Immortal;

use crate::{config::UdpForwardConfig, daemon::socket::Socket};

use super::DaemonContext;

/// Loop that forwards a remote earendil address to a local udp port
pub async fn udp_forward_loop(
    ctx: DaemonContext,
    udp_fwd_cfg: UdpForwardConfig,
) -> anyhow::Result<()> {
    async fn udp_forward_down_loop(
        earendil_skt: Arc<Socket>,
        udp_skt: Arc<UdpSocket>,
        udp_dest: SocketAddr,
    ) -> anyhow::Result<()> {
        loop {
            let (msg, _) = earendil_skt.recv_from().await?;
            udp_skt.send_to(&msg, udp_dest).await?;
        }
    }

    let demux_table: Cache<SocketAddr, (Arc<Socket>, Arc<Immortal>)> = Cache::new(10_000);
    let udp_socket = Arc::new(
        UdpSocket::bind(SocketAddrV4::new(
            "127.0.0.1".parse()?,
            udp_fwd_cfg.forward_to,
        ))
        .await?,
    );
    let mut buf = [0; 10_000];
    loop {
        // read a message from the udp socket
        let (n, src_udp_addr) = udp_socket.recv_from(&mut buf).await?;
        let msg = buf[..n].to_vec();

        // get the earendil socket for the src_udp_addr. If it doesn't exist, create one
        // and spawn a loop that forwards messages from the earendil socket back to the src_udp_addr
        let src_earendil_skt = demux_table.get_with(src_udp_addr, || {
            let earendil_skt = Arc::new(Socket::bind_haven(
                &ctx,
                Some(IdentitySecret::generate()),
                None,
                None,
            ));
            let down_loop = Immortal::respawn(
                smolscale::immortal::RespawnStrategy::Immediate,
                clone!([earendil_skt, udp_socket], move || {
                    udp_forward_down_loop(
                        earendil_skt.clone(),
                        udp_socket.clone(),
                        src_udp_addr.clone(),
                    )
                }),
            );
            (earendil_skt, Arc::new(down_loop))
        });

        // forward the message to the remote earendil endpoint
        // using the earendil socket associated with the src_udp_addr
        src_earendil_skt
            .0
            .send_to(msg.into(), udp_fwd_cfg.remote_ep)
            .await?;
    }
}
