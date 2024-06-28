mod control_protocol_impl;

use std::{convert::Infallible, net::Ipv4Addr, str::FromStr, sync::Arc};

use anyhow::Context;
use async_trait::async_trait;
use clone_macro::clone;
use control_protocol_impl::ControlProtocolImpl;
use earendil_crypt::{HavenEndpoint, HavenFingerprint, HavenIdentitySecret, RelayFingerprint};
use futures::task::noop_waker;
use futures::{future::Shared, stream::FuturesUnordered, AsyncReadExt, TryFutureExt};
use melstructs::NetID;
use nanorpc::{JrpcRequest, JrpcResponse, RpcService, RpcTransport};
use nanorpc_http::server::HttpRpcServer;
use nursery_macro::nursery;
use smol::{
    future::FutureExt,
    net::{TcpListener, TcpStream},
    stream::StreamExt,
};
use smolscale::immortal::{Immortal, RespawnStrategy};
use socksv5::v5::{
    read_handshake, read_request, write_auth_method, write_request_status, SocksV5AuthMethod,
    SocksV5Host, SocksV5RequestStatus,
};
use tracing::instrument;

use crate::{
    config::{ConfigFile, HavenConfig, HavenHandler, RelayConfig, Socks5Config, Socks5Fallback},
    control_protocol::{ControlClient, ControlService},
    link_node::{LinkConfig, LinkNode},
    n2r_node::{N2rConfig, N2rNode},
    v2h_node::{HavenListener, HavenPacketConn, PooledListener, PooledVisitor, V2hConfig, V2hNode},
};
use crate::{Dummy, NodeId, OnChain, PaymentSystem, PoW};

/// The public interface to the whole Earendil system.
pub struct Node {
    ctx: NodeCtx,
    task: Shared<smol::Task<Result<(), Arc<anyhow::Error>>>>,
}

#[derive(Clone)]
pub struct NodeCtx {
    v2h: Arc<V2hNode>,
    config: ConfigFile,
}

impl Node {
    pub async fn start(config: ConfigFile) -> anyhow::Result<Self> {
        let config_clone = config.clone();
        let mel_client = Arc::new(if let Some(bootstrap_route) = config.mel_bootstrap {
            melprot::Client::connect_with_proxy(
                NetID::Mainnet,
                config.socks5.listen,
                bootstrap_route,
            )
            .await?
        } else {
            melprot::Client::autoconnect(NetID::Mainnet).await?
        });

        // construct payment systems based on our config
        let mut payment_systems: Vec<Box<dyn PaymentSystem>> = vec![];
        if config.payment_methods.dummy.is_some() {
            payment_systems.push(Box::new(Dummy::new()));
        }
        if config.payment_methods.pow.is_some() {
            payment_systems.push(Box::new(PoW::new(mel_client.clone())));
        }
        if let Some(crate::config::OnChain { secret }) = config.payment_methods.onchain {
            payment_systems.push(Box::new(OnChain::new(&secret, mel_client.clone())?))
        }

        let link = LinkNode::new(
            LinkConfig {
                relay_config: config.relay_config.clone().map(
                    |RelayConfig {
                         identity,
                         in_routes,
                     }| (identity.actualize_relay().unwrap(), in_routes),
                ),
                out_routes: config.out_routes.clone(),
                payment_systems,
                db_path: config.db_path.unwrap_or_else(|| {
                    let mut data_dir = dirs::data_dir().unwrap();
                    data_dir.push("earendil-link-store.db");
                    data_dir
                }),
            },
            mel_client,
        )?;

        let n2r = N2rNode::new(link, N2rConfig {});
        let v2h = Arc::new(V2hNode::new(
            n2r,
            V2hConfig {
                is_relay: config.relay_config.is_some(),
            },
        ));

        // start loops for handling socks5, etc, etc
        let v2h_clone = v2h.clone();
        let ctx = NodeCtx {
            v2h,
            config: config_clone,
        };

        let ctx_clone = ctx.clone();
        let daemon_loop = async move {
            let _control_protocol = Immortal::respawn(
                RespawnStrategy::Immediate,
                clone!([ctx_clone], move || control_protocol_loop(
                    ctx_clone.clone()
                )
                .map_err(|e| tracing::warn!("control_protocol_loop restart: {e}"))),
            );

            nursery!({
                let mut fallible_tasks = FuturesUnordered::new();
                // for every haven, serve the haven
                for haven_cfg in config.havens {
                    fallible_tasks.push(spawn!(serve_haven(v2h_clone.clone(), haven_cfg)))
                }

                // serve socks5
                fallible_tasks.push(spawn!(socks5_loop(v2h_clone.clone(), config.socks5)));

                // Join all the tasks. If any of the tasks terminate with an error, that's fatal!
                while let Some(next) = fallible_tasks.next().await {
                    next?;
                }
                anyhow::Ok(())
            })
        };
        let task = smolscale::spawn(daemon_loop.map_err(Arc::new));

        Ok(Self {
            ctx,
            task: futures::FutureExt::shared(task),
        })
    }

    pub async fn wait_until_dead(self) -> anyhow::Result<()> {
        self.task.await.map_err(|e| anyhow::anyhow!(e))
    }

    pub fn check_dead(&self) -> anyhow::Result<()> {
        match smol::future::FutureExt::poll(
            &mut self.task.clone(),
            &mut core::task::Context::from_waker(&noop_waker()),
        ) {
            std::task::Poll::Ready(val) => val.map_err(|e| anyhow::anyhow!(e))?,
            std::task::Poll::Pending => {}
        }
        Ok(())
    }

    /// Creates a low-level, unreliable packet connection.
    pub async fn packet_connect(&self, dest: HavenEndpoint) -> anyhow::Result<HavenPacketConn> {
        self.ctx.v2h.packet_connect(dest).await
    }

    /// Creates a low-level, unreliable packet listener.
    pub async fn packet_listen(
        &self,
        identity: HavenIdentitySecret,
        port: u16,
        rendezvous: RelayFingerprint,
    ) -> anyhow::Result<HavenListener> {
        self.ctx.v2h.packet_listen(identity, port, rendezvous).await
    }

    /// Creates a new pooled visitor. Under Earendil's anonymity model, each visitor should be unlinkable to any other visitor, but streams created within each visitor are linkable to the same haven each other by the haven (though not by the network).
    pub async fn pooled_visitor(&self) -> PooledVisitor {
        self.ctx.v2h.pooled_visitor().await
    }

    /// Creates a new pooled listener.
    pub async fn pooled_listen(
        &self,
        identity: HavenIdentitySecret,
        port: u16,
        rendezvous: RelayFingerprint,
    ) -> anyhow::Result<PooledListener> {
        self.ctx.v2h.pooled_listen(identity, port, rendezvous).await
    }

    pub fn control_client(&self) -> ControlClient {
        ControlClient::from(DummyControlProtocolTransport {
            inner: ControlService(ControlProtocolImpl::new(self.ctx.clone())),
        })
    }

    pub fn identity(&self) -> NodeId {
        self.ctx.v2h.link_node().my_id().public()
    }
}
struct DummyControlProtocolTransport {
    inner: ControlService<ControlProtocolImpl>,
}

#[async_trait]
impl RpcTransport for DummyControlProtocolTransport {
    type Error = Infallible;

    async fn call_raw(&self, req: JrpcRequest) -> Result<JrpcResponse, Self::Error> {
        Ok(self.inner.respond_raw(req).await)
    }
}

#[instrument(skip(ctx))]
/// Loop that handles the control protocol
async fn control_protocol_loop(ctx: NodeCtx) -> anyhow::Result<()> {
    let http = HttpRpcServer::bind(ctx.config.control_listen).await?;
    let service = ControlService(ControlProtocolImpl::new(ctx));
    http.run(service).await?;
    Ok(())
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
