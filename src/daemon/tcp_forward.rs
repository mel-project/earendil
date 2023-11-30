use std::net::SocketAddrV4;

use earendil_crypt::IdentitySecret;
use futures_util::io;
use smol::{future::FutureExt, net::TcpListener};
use smolscale::reaper::TaskReaper;

use crate::{config::TcpForwardConfig, socket::Socket, stream::Stream};

use super::DaemonContext;

pub async fn tcp_forward_loop(
    ctx: DaemonContext,
    tcp_fwd_cfg: TcpForwardConfig,
) -> anyhow::Result<()> {
    log::debug!("tcp forward loop");
    let tcp_listener = TcpListener::bind(SocketAddrV4::new(
        "127.0.0.1".parse()?,
        tcp_fwd_cfg.forward_to,
    ))
    .await?;
    let reaper = TaskReaper::new();

    loop {
        let (tcp_stream, _) = tcp_listener.accept().await?;
        let earendil_socket =
            Socket::bind_haven_internal(ctx.clone(), IdentitySecret::generate(), None, None);
        let earendil_stream = Stream::connect(earendil_socket, tcp_fwd_cfg.remote_ep).await?;
        reaper.attach(smolscale::spawn(async move {
            loop {
                io::copy(tcp_stream.clone(), &mut earendil_stream.clone())
                    .race(io::copy(earendil_stream.clone(), &mut tcp_stream.clone()))
                    .await?;
            }
            anyhow::Ok(())
        }));
    }
}
