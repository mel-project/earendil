use earendil_crypt::HavenIdentitySecret;
use futures_util::io;
use nursery_macro::nursery;
use smol::{future::FutureExt, net::TcpListener};

use crate::{
    config::TcpForwardConfig,
    socket::{Endpoint, Socket},
    stream::Stream,
};

use super::DaemonContext;

#[tracing::instrument(skip(ctx))]
pub async fn tcp_forward_loop(
    ctx: DaemonContext,
    tcp_fwd_cfg: TcpForwardConfig,
) -> anyhow::Result<()> {
    tracing::debug!("tcp forward loop start");
    let tcp_listener = TcpListener::bind(tcp_fwd_cfg.listen).await?;

    nursery!(loop {
        let (tcp_stream, _) = tcp_listener.accept().await?;
        let client_addr = tcp_stream.peer_addr()?;
        tracing::debug!(client_addr = ?client_addr, "connecting to remote...");
        let earendil_socket =
            Socket::bind_haven_internal(ctx.clone(), HavenIdentitySecret::generate(), None, None);
        let earendil_stream =
            Stream::connect(earendil_socket, Endpoint::Haven(tcp_fwd_cfg.remote)).await?;
        tracing::debug!(client_addr = ?client_addr, "connected successfully");
        spawn!(async move {
            io::copy(tcp_stream.clone(), &mut earendil_stream.clone())
                .race(io::copy(earendil_stream.clone(), &mut tcp_stream.clone()))
                .await?;
            anyhow::Ok(())
        })
        .detach();
    })
}
