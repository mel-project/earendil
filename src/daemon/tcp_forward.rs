use std::{net::SocketAddrV4, sync::Arc};

use clone_macro::clone;
use earendil_crypt::IdentitySecret;
use smol::{
    future::FutureExt,
    io::{AsyncReadExt, AsyncWriteExt},
    lock::RwLock,
    net::{TcpListener, TcpStream},
};
use smolscale::immortal::Immortal;

use crate::{config::TcpForwardConfig, socket::Socket, stream::Stream};

use super::DaemonContext;

pub async fn tcp_forward_loop(
    ctx: DaemonContext,
    tcp_fwd_cfg: TcpForwardConfig,
) -> anyhow::Result<()> {
    async fn stream_loop(
        earendil_stream: Arc<RwLock<Stream>>,
        tcp_stream: Arc<RwLock<TcpStream>>,
    ) -> anyhow::Result<()> {
        let down = async {
            loop {
                let mut buf = [0u8; 1000];
                let mut earendil_stream = earendil_stream.write().await;
                let n = earendil_stream.read(&mut buf).await?;
                let mut tcp_stream = tcp_stream.write().await;
                tcp_stream.write(&buf[..n]).await?;
            }
            anyhow::Ok(())
        };

        let up = async {
            loop {
                let mut buf = [0u8; 1000];
                let mut tcp_stream = tcp_stream.write().await;
                let n = tcp_stream.read(&mut buf).await?;
                let mut earendil_stream = earendil_stream.write().await;
                earendil_stream.write(&buf[..n]).await?;
            }
            anyhow::Ok(())
        };

        up.race(down).await?;

        Ok(())
    }

    let tcp_listener = TcpListener::bind(SocketAddrV4::new(
        "127.0.0.1".parse()?,
        tcp_fwd_cfg.forward_to,
    ))
    .await?;

    let mut stream_loops = vec![];

    loop {
        let (tcp_stream, _) = tcp_listener.accept().await?;
        let tcp_stream = Arc::new(RwLock::new(tcp_stream));

        let earendil_socket =
            Socket::bind_haven_internal(ctx.clone(), IdentitySecret::generate(), None, None);
        let earendil_stream = Arc::new(RwLock::new(
            Stream::connect(earendil_socket, tcp_fwd_cfg.remote_ep).await?,
        ));

        let stream_loop = Immortal::respawn(
            smolscale::immortal::RespawnStrategy::Immediate,
            clone!([earendil_stream, tcp_stream], move || {
                stream_loop(earendil_stream.clone(), tcp_stream.clone())
            }),
        );

        stream_loops.push(stream_loop);
    }
}
