use anyhow::Context as _;
use earendil_crypt::HavenFingerprint;
use futures::AsyncReadExt;
use futures_util::TryFutureExt;
use nursery_macro::nursery;
use smol::{
    future::FutureExt as _,
    net::{TcpListener, TcpStream},
};
use socksv5::v5::{
    read_handshake, read_request, write_auth_method, write_request_status, SocksV5AuthMethod,
    SocksV5Host, SocksV5RequestStatus,
};
use std::{net::Ipv4Addr, str::FromStr as _};

use crate::{context::DaemonContext, HavenEndpoint, PooledVisitor, Socks5Config, Socks5Fallback};

pub async fn socks5_loop(ctx: &DaemonContext, socks5_cfg: Socks5Config) -> anyhow::Result<()> {
    let tcp_listener = TcpListener::bind(socks5_cfg.listen).await?;
    let fallback = socks5_cfg.fallback;
    let pool = PooledVisitor::new(ctx.clone());

    nursery!(loop {
        let (client_stream, _) = tcp_listener.accept().await?;
        spawn!(socks5_once(&ctx, client_stream, fallback, &pool)
            .map_err(|e| tracing::debug!(err = debug(e), "socks5 worker failed")))
        .detach();
    })
}

#[tracing::instrument(skip(ctx, client_stream, fallback, pool))]
async fn socks5_once(
    ctx: &DaemonContext,
    client_stream: TcpStream,
    fallback: Socks5Fallback,
    pool: &PooledVisitor,
) -> anyhow::Result<()> {
    client_stream.set_nodelay(true)?;
    let _handshake = read_handshake(client_stream.clone()).await?;
    write_auth_method(client_stream.clone(), SocksV5AuthMethod::Noauth).await?;
    let request = read_request(client_stream.clone()).await?;
    let port = request.port;
    let domain: String = match &request.host {
        SocksV5Host::Domain(dom) => String::from_utf8_lossy(dom).parse()?,
        SocksV5Host::Ipv4(v4) => {
            let v4addr = Ipv4Addr::new(v4[0], v4[1], v4[2], v4[3]);
            v4addr.to_string()
        }
        _ => anyhow::bail!("IPv6 not supported"),
    };
    let addr = format!("{domain}:{port}");

    write_request_status(
        client_stream.clone(),
        SocksV5RequestStatus::Success,
        request.host,
        port,
    )
    .await?;

    tracing::debug!(addr = debug(&addr), "socks5 received request");

    let mut split_domain = domain.split('.');
    let top_level = split_domain.clone().last();

    if let Some(top) = top_level {
        if top == "haven" {
            let endpoint = HavenEndpoint::new(
                HavenFingerprint::from_str(
                    split_domain.next().context("invalid Earendil address")?,
                )?,
                port.into(),
            );
            let earendil_stream = pool.connect(endpoint, b"").await?;
            let (read, write) = earendil_stream.split();
            smol::io::copy(read, client_stream.clone())
                .race(smol::io::copy(client_stream.clone(), write))
                .await?;
        } else {
            match fallback {
                Socks5Fallback::Block => return Ok(()),
                Socks5Fallback::PassThrough => {
                    let passthrough_stream = TcpStream::connect(addr).await?;
                    smol::io::copy(client_stream.clone(), passthrough_stream.clone())
                        .race(smol::io::copy(
                            passthrough_stream.clone(),
                            client_stream.clone(),
                        ))
                        .await?;
                }
                Socks5Fallback::SimpleProxy { remote } => {
                    let remote_stream = pool.connect(remote, addr.as_bytes()).await?;
                    let (read, write) = remote_stream.split();
                    smol::io::copy(client_stream.clone(), write)
                        .race(smol::io::copy(read, client_stream.clone()))
                        .await?;
                }
            }
        }
    }

    Ok(())
}
