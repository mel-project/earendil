use std::{net::Ipv4Addr, str::FromStr, sync::Arc};

use anyhow::Context;
use earendil_crypt::{HavenEndpoint, HavenFingerprint, HavenIdentitySecret, RelayFingerprint};
use futures::{future::Shared, stream::FuturesUnordered, AsyncReadExt, TryFutureExt};
use nursery_macro::nursery;
use smol::{
    future::FutureExt,
    net::{TcpListener, TcpStream},
    stream::StreamExt,
};
use socksv5::v5::{
    read_handshake, read_request, write_auth_method, write_request_status, SocksV5AuthMethod,
    SocksV5Host, SocksV5RequestStatus,
};

use crate::{
    config::{ConfigFile, HavenConfig, HavenHandler, Socks5Config, Socks5Fallback},
    link_node::{LinkConfig, LinkNode},
    n2r_node::{N2rConfig, N2rNode},
    v2h_node::{HavenListener, HavenPacketConn, PooledListener, PooledVisitor, V2hConfig, V2hNode},
};

/// The public interface to the whole Earendil system.
pub struct Node {
    v2h: Arc<V2hNode>,
    task: Shared<smol::Task<Result<(), Arc<anyhow::Error>>>>,
}

impl Node {
    pub fn new(config: ConfigFile) -> anyhow::Result<Self> {
        let link = LinkNode::new(LinkConfig {
            in_routes: config.in_routes.clone(),
            out_routes: config.out_routes.clone(),
            my_idsk: if let Some(id) = config.identity {
                Some(id.actualize_relay()?)
            } else {
                None
            },
            db_path: config.db_path.unwrap_or_else(|| {
                let mut data_dir = dirs::data_dir().unwrap();
                data_dir.push("earendil-link-store.db");
                data_dir
            }),
        });
        let n2r = N2rNode::new(link, N2rConfig {});
        let v2h = Arc::new(V2hNode::new(n2r, V2hConfig {}));

        // start loops for handling socks5, etc, etc
        let v2h_clone = v2h.clone();
        let daemon_loop = async move {
            if config.havens.is_empty() && config.socks5.is_none() {
                smol::future::pending().await
            } else {
                nursery!({
                    let mut fallible_tasks = FuturesUnordered::new();
                    // for every haven, serve the haven
                    for haven_cfg in config.havens {
                        fallible_tasks.push(spawn!(serve_haven(v2h_clone.clone(), haven_cfg)))
                    }
                    // serve socks5 if config has it
                    if let Some(socks5_cfg) = config.socks5 {
                        fallible_tasks.push(spawn!(socks5_loop(v2h_clone.clone(), socks5_cfg)))
                    }
                    // Join all the tasks. If any of the tasks terminate with an error, that's fatal!
                    while let Some(next) = fallible_tasks.next().await {
                        next?;
                    }
                    anyhow::Ok(())
                })
            }
        };
        let task = smolscale::spawn(daemon_loop.map_err(Arc::new));

        Ok(Self {
            v2h,
            task: futures::FutureExt::shared(task),
        })
    }

    pub async fn wait_until_dead(self) -> anyhow::Result<()> {
        self.task.await.map_err(|e| anyhow::anyhow!(e))
    }

    /// Creates a low-level, unreliable packet connection.
    pub async fn packet_connect(&self, dest: HavenEndpoint) -> anyhow::Result<HavenPacketConn> {
        self.v2h.packet_connect(dest).await
    }

    /// Creates a low-level, unreliable packet listener.
    pub async fn packet_listen(
        &self,
        identity: HavenIdentitySecret,
        port: u16,
        rendezvous: RelayFingerprint,
    ) -> anyhow::Result<HavenListener> {
        self.v2h.packet_listen(identity, port, rendezvous).await
    }

    /// Creates a new pooled visitor. Under Earendil's anonymity model, each visitor should be unlinkable to any other visitor, but streams created within each visitor are linkable to the same haven each other by the haven (though not by the network).
    pub async fn pooled_visitor(&self) -> PooledVisitor {
        self.v2h.pooled_visitor().await
    }

    /// Creates a new pooled listener.
    pub async fn pooled_listen(
        &self,
        identity: HavenIdentitySecret,
        port: u16,
        rendezvous: RelayFingerprint,
    ) -> anyhow::Result<PooledListener> {
        self.v2h.pooled_listen(identity, port, rendezvous).await
    }
}

async fn serve_haven(v2h: Arc<V2hNode>, cfg: HavenConfig) -> anyhow::Result<()> {
    let identity = cfg.identity.actualize_haven()?;
    let listener = v2h
        .pooled_listen(identity, cfg.listen_port, cfg.rendezvous)
        .await?;
    nursery!({
        let handler = cfg.handler.clone();
        loop {
            let client = listener
                .accept()
                .await
                .context("could not accept another from PooledListener")?;
            let handler = handler.clone();
            spawn!(async move {
                match handler {
                    HavenHandler::TcpService { upstream } => {
                        tracing::debug!(upstream = debug(upstream), "serving a tcp service");
                        let upstream = smol::net::TcpStream::connect(upstream).await?;
                        let (read_client, write_client) = client.split();
                        smol::io::copy(read_client, upstream.clone())
                            .race(smol::io::copy(upstream.clone(), write_client))
                            .await?
                    }
                    HavenHandler::SimpleProxy => {
                        let connect_to = String::from_utf8_lossy(client.metadata());
                        tracing::debug!(connect_to = debug(&connect_to), "serving SimpleProxy");
                        let upstream =
                            smol::net::TcpStream::connect(connect_to.to_string()).await?;
                        let (read_client, write_client) = client.split();
                        smol::io::copy(read_client, upstream.clone())
                            .race(smol::io::copy(upstream.clone(), write_client))
                            .await?
                    }
                };
                anyhow::Ok(())
            })
            .detach()
        }
    })
}

async fn socks5_loop(v2h: Arc<V2hNode>, cfg: Socks5Config) -> anyhow::Result<()> {
    let tcp_listener = TcpListener::bind(cfg.listen).await?;
    let fallback = cfg.fallback;
    let pool = v2h.pooled_visitor().await;

    nursery!(loop {
        let (client_stream, _) = tcp_listener.accept().await?;
        spawn!(socks5_once(client_stream, fallback, &pool)
            .map_err(|e| tracing::debug!(err = debug(e), "socks5 worker failed")))
        .detach();
    })
}

#[tracing::instrument(skip(client_stream, fallback, pool))]
async fn socks5_once(
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
                port,
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
                    tracing::debug!(addr = debug(&addr), "got remote stream");
                    let (read, write) = remote_stream.split();
                    match smol::io::copy(client_stream.clone(), write)
                        .race(smol::io::copy(read, client_stream.clone()))
                        .await
                    {
                        Ok(x) => tracing::debug!("RETURNED with {x}"),
                        Err(e) => tracing::debug!("RETURNED with ERR: {e}"),
                    }
                }
            }
        }
    }
    Ok(())
}
