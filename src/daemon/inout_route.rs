use std::{net::SocketAddr, sync::Arc, time::Duration};

use earendil_crypt::{ClientId, RelayFingerprint};
use earendil_topology::IdentityDescriptor;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite};
use futures_util::TryFutureExt;
use nursery_macro::nursery;
use serde::{Deserialize, Serialize};
use smol::{future::FutureExt, io::AsyncWriteExt};
use smol_timeout::TimeoutExt;

use sosistab2::{Multiplex, MuxSecret};
use sosistab2_obfsudp::{ObfsUdpListener, ObfsUdpPipe, ObfsUdpPublic, ObfsUdpSecret};
use stdcode::StdcodeSerializeExt;
pub mod chat;
mod link_connection;
mod link_protocol;
use crate::{config::LinkPrice, network};
use crate::{
    context::{DaemonContext, MY_CLIENT_ID, MY_RELAY_IDENTITY, MY_RELAY_ONION_SK},
    daemon::inout_route::link_connection::{ClientNeighbor, RelayNeighbor},
};

use self::{
    link_connection::{gossip_loop, link_maintain, LinkContext, LinkProtocolImpl},
    link_protocol::{LinkClient, LinkService},
};

const CONNECTION_LIFETIME: Duration = Duration::from_secs(10);

#[derive(Serialize, Deserialize)]
enum LinkHello {
    Client(ClientId),
    Relay(IdentityDescriptor),
}

#[derive(Clone)]
pub struct InRouteContext {
    pub daemon_ctx: DaemonContext,
    pub in_route_name: String,
}

#[tracing::instrument(skip(context, secret))]
pub async fn in_route_obfsudp(
    context: InRouteContext,
    listen: SocketAddr,
    secret: String,
    link_price: LinkPrice,
) -> anyhow::Result<()> {
    let secret = ObfsUdpSecret::from_bytes(*blake3::hash(secret.as_bytes()).as_bytes());
    tracing::debug!(
        "obfsudp in_route {} listen start with cookie {}",
        context.in_route_name,
        hex::encode(secret.to_public().as_bytes())
    );
    let listener = ObfsUdpListener::bind(listen, secret).await?;
    nursery!(loop {
        let pipe = listener.accept().await?;
        let mplex = Arc::new(Multiplex::new(MuxSecret::generate(), None));
        mplex.add_pipe(pipe);
        let context = context.clone();
        spawn!(
            route_loop(context.daemon_ctx.clone(), mplex, link_price, true)
                .timeout(CONNECTION_LIFETIME)
        )
        .detach();
    })
}

async fn route_loop(
    ctx: DaemonContext,
    mplex: Arc<Multiplex>,
    link_price: LinkPrice,
    is_listen: bool,
) -> anyhow::Result<()> {
    tracing::debug!(is_listen, "route loop started");
    scopeguard::defer!(tracing::info!(is_listen, "route loop stopped"));
    // first, we authenticate the other side.
    let neighbor: either::Either<IdentityDescriptor, ClientId> = {
        let stream = if is_listen {
            let s = mplex.accept_conn().await?;
            tracing::debug!("accepted the authentication stream");
            s
        } else {
            let s = mplex.open_conn("!init_auth").await?;
            tracing::debug!("made the authentication stream");
            s
        };

        let (mut read, mut write) = stream.split();
        let send_hello_fut = async {
            if ctx.init().is_client() {
                write_msg(
                    &LinkHello::Client(*ctx.get(MY_CLIENT_ID)).stdcode(),
                    &mut write,
                )
                .await?;
            } else {
                write_msg(
                    &LinkHello::Relay(IdentityDescriptor::new(
                        &ctx.get(MY_RELAY_IDENTITY)
                            .expect("only relays have global identities"),
                        ctx.get(MY_RELAY_ONION_SK),
                    ))
                    .stdcode(),
                    &mut write,
                )
                .await?;
            }
            anyhow::Ok(())
        };
        let read_hello_fut = async {
            let hello: LinkHello = stdcode::deserialize(&read_msg(&mut read).await?)?;
            anyhow::Ok(hello)
        };
        let (a, their_hello) = futures::join!(send_hello_fut, read_hello_fut);
        a?;
        match their_hello? {
            LinkHello::Client(c) => either::Right(c),
            LinkHello::Relay(r) => either::Left(r),
        }
    };

    tracing::debug!(
        is_listen,
        neighbor = debug(&neighbor),
        "authentication done"
    );

    // then, we start the link maintenance
    let link_channel_and_neigh = neighbor
        .as_ref()
        .map_left(|left| {
            RelayNeighbor(
                network::subscribe_outgoing_relay(&ctx, left.identity_pk.fingerprint()),
                left.identity_pk.fingerprint(),
            )
        })
        .map_right(|right| {
            ClientNeighbor(network::subscribe_outgoing_client(&ctx, *right), *right)
        });
    let link_context = LinkContext {
        ctx: ctx.clone(),
        service: Arc::new(LinkService(LinkProtocolImpl {
            ctx: ctx.clone(),
            mplex: mplex.clone(),
            remote: neighbor,
            max_outgoing_price: link_price.max_outgoing_price,
        })),
        mplex,
        neighbor: link_channel_and_neigh,
    };
    let link_maintenance = link_maintain(&link_context, is_listen);
    let gossip = gossip_loop(&link_context);

    link_maintenance.race(gossip).await
}

#[derive(Clone)]
pub struct OutRouteContext {
    pub daemon_ctx: DaemonContext,
    pub out_route_name: String,
    pub remote_fingerprint: RelayFingerprint,
}

#[tracing::instrument(skip(context, cookie))]
pub async fn out_route_obfsudp(
    context: OutRouteContext,
    connect: SocketAddr,
    cookie: [u8; 32],
    link_price: LinkPrice,
) -> anyhow::Result<()> {
    let mut timer1 = smol::Timer::interval(CONNECTION_LIFETIME);
    let mut timer2 = smol::Timer::interval(CONNECTION_LIFETIME);
    let ctx = context.daemon_ctx;

    loop {
        let fallible = async {
            tracing::debug!("{} trying...", context.out_route_name);
            let pipe = ObfsUdpPipe::connect(connect, ObfsUdpPublic::from_bytes(cookie), "").await?;
            tracing::info!("{} pipe connected", context.out_route_name);

            let mplex = Arc::new(Multiplex::new(MuxSecret::generate(), None));
            mplex.add_pipe(pipe);

            let out_route_loop = route_loop(ctx.clone(), mplex, link_price, false);

            out_route_loop
                .map_err(|e| {
                    tracing::warn!(
                        "out route loop for {:?} died: {:?}",
                        context.remote_fingerprint,
                        e
                    );
                    e
                })
                .await?;

            anyhow::Ok(())
        };

        async {
            if let Err(err) = fallible.await {
                tracing::warn!(
                    "obfs out_route {} failed: {:?}",
                    context.out_route_name,
                    err
                );
            }
            (&mut timer1).await;
        }
        .or(async {
            (&mut timer2).await;
        })
        .await;
    }
}

pub async fn write_msg<W: AsyncWrite + Unpin>(message: &[u8], mut out: W) -> anyhow::Result<()> {
    let len = (message.len() as u32).to_be_bytes();

    out.write_all(&len).await?;
    out.write_all(message).await?;
    out.flush().await?;

    Ok(())
}

pub async fn read_msg<R: AsyncRead + Unpin>(mut input: R) -> anyhow::Result<Vec<u8>> {
    let mut len = [0; 4];
    input.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len);

    let mut buffer = vec![0; len as usize];
    input.read_exact(&mut buffer).await?;

    Ok(buffer)
}
