use std::{net::Ipv4Addr, str::FromStr};

use anyhow::Context;
use earendil_crypt::{HavenFingerprint, HavenIdentitySecret};
use futures_util::{io, TryFutureExt};
use nursery_macro::nursery;
use smol::{
    future::FutureExt,
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
};

use socksv5::v5::*;

use crate::{
    config::{Fallback, Socks5},
    socket::{Endpoint, HavenEndpoint, Socket},
    stream::Stream,
};

use crate::context::{CtxField, DaemonContext};

#[tracing::instrument(skip(ctx))]
pub async fn socks5_loop(ctx: DaemonContext, socks5_cfg: Socks5) -> anyhow::Result<()> {
    tracing::debug!("started");
    let tcp_listener = TcpListener::bind(socks5_cfg.listen).await?;
    let fallback = socks5_cfg.fallback;

    nursery!(loop {
        let (client_stream, _) = tcp_listener.accept().await?;
        spawn!(socks5_once(&ctx, client_stream, fallback)
            .map_err(|e| tracing::debug!("worker failed: {:?}", e)))
        .detach();
    })
}

// this makes reply block handling a bit more efficient at the cost of some anonymity --- we should investigate a better way
static SOCKS5_LOCAL_IDSK: CtxField<HavenIdentitySecret> = |_| HavenIdentitySecret::generate();

#[tracing::instrument(skip(ctx, client_stream, fallback))]
async fn socks5_once(
    ctx: &DaemonContext,
    client_stream: TcpStream,
    fallback: Fallback,
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

    tracing::info!("socks5 received request for {addr}");

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
            let earendil_skt =
                Socket::bind_haven_internal(ctx.clone(), *ctx.get(SOCKS5_LOCAL_IDSK), None, None);
            let earendil_stream = Stream::connect(earendil_skt, Endpoint::Haven(endpoint)).await?;

            io::copy(client_stream.clone(), &mut earendil_stream.clone())
                .race(io::copy(
                    earendil_stream.clone(),
                    &mut client_stream.clone(),
                ))
                .await?;
        } else {
            match fallback {
                Fallback::Block => return Ok(()),
                Fallback::PassThrough => {
                    let passthrough_stream = TcpStream::connect(addr).await?;
                    io::copy(client_stream.clone(), &mut passthrough_stream.clone())
                        .race(io::copy(
                            passthrough_stream.clone(),
                            &mut client_stream.clone(),
                        ))
                        .await?;
                }
                Fallback::SimpleProxy { remote } => {
                    let remote_skt = Socket::bind_haven_internal(
                        ctx.clone(),
                        *ctx.get(SOCKS5_LOCAL_IDSK),
                        None,
                        None,
                    );
                    let mut remote_stream =
                        Stream::connect(remote_skt, Endpoint::Haven(remote)).await?;
                    let prepend = (addr.len() as u16).to_be_bytes();
                    remote_stream.write(&prepend).await?;

                    remote_stream.write(addr.as_bytes()).await?;

                    io::copy(client_stream.clone(), &mut remote_stream.clone())
                        .race(io::copy(remote_stream.clone(), &mut client_stream.clone()))
                        .await?;
                }
            }
        }
    }

    Ok(())
}
