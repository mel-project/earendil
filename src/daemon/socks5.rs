use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs},
    str::FromStr,
};

use anyhow::Context;
use earendil_crypt::Fingerprint;
use futures_util::io;
use smol::{
    future::FutureExt,
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
};
use smolscale::reaper::TaskReaper;
use socksv5::v5::*;

use crate::{
    config::{Fallback, Socks5},
    socket::{Endpoint, Socket},
    stream::Stream,
};

use super::DaemonContext;

pub async fn socks5_loop(ctx: DaemonContext, socks5_cfg: Socks5) -> anyhow::Result<()> {
    log::debug!("socks5 loop started");
    let tcp_listener = TcpListener::bind(SocketAddrV4::new(
        "127.0.0.1".parse()?,
        socks5_cfg.listen_port,
    ))
    .await?;
    let fallback = socks5_cfg.fallback;
    let reaper = TaskReaper::new();

    loop {
        let ctx = ctx.clone();
        let fallback = fallback.clone();
        let (client_stream, _) = tcp_listener.accept().await?;

        reaper.attach(smolscale::spawn(async move {
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

            log::info!("socks5 received request for {addr}");

            let mut split_domain = domain.split('.');
            let top_level = split_domain.clone().last();

            if let Some(top) = top_level {
                if top == "haven" {
                    let endpoint = Endpoint::new(
                        Fingerprint::from_str(
                            split_domain.next().context("invalid Earendil address")?,
                        )?,
                        port.into(),
                    );
                    let earendil_skt =
                        Socket::bind_haven_internal(ctx.clone(), ctx.identity, None, None);
                    let earendil_stream = Stream::connect(earendil_skt, endpoint).await?;

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
                        Fallback::SimpleProxy { remote_ep } => {
                            let remote_skt =
                                Socket::bind_haven_internal(ctx.clone(), ctx.identity, None, None);
                            let mut remote_stream = Stream::connect(remote_skt, remote_ep).await?;
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
        }));
    }
}
