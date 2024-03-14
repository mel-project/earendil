use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use earendil_crypt::{ClientId, RelayFingerprint, RelayIdentityPublic};
use earendil_packet::{RawBody, RawPacket};
use earendil_topology::IdentityDescriptor;
use futures::{AsyncRead, AsyncWrite};
use futures_util::TryFutureExt;
use nursery_macro::nursery;
use serde::{Deserialize, Serialize};
use smol::{
    channel::Receiver,
    future::FutureExt,
    io::{AsyncReadExt, AsyncWriteExt},
};
use smol_timeout::TimeoutExt;

use sosistab2::{Multiplex, MuxSecret};
use sosistab2_obfsudp::{ObfsUdpListener, ObfsUdpPipe, ObfsUdpPublic, ObfsUdpSecret};
pub mod chat;
mod gossip;
mod link_connection;
mod link_protocol;
use crate::{
    config::{AutoSettle, LinkPrice},
    daemon::inout_route::{
        chat::{add_client_link, add_relay_link, remove_client_link, remove_relay_link},
        gossip::{
            client_gossip_with_relay_loop, gossip_with_client_loop, relay_gossip_with_relay_loop,
        },
    },
    settlement::{difficulty_to_micromel, onchain_multiplier, SettlementProof, SettlementRequest},
};
use crate::{
    context::{
        DaemonContext, CLIENT_TABLE, DEBTS, GLOBAL_IDENTITY, GLOBAL_ONION_SK, MY_CLIENT_ID,
        NEIGH_TABLE_NEW, SETTLEMENTS,
    },
    daemon::inout_route::link_connection::{ClientNeighbor, RelayNeighbor},
};

use self::{
    link_connection::{link_maintain, LinkContext, LinkProtocolImpl, LinkRpcTransport},
    link_protocol::{LinkClient, LinkService},
};

const CONNECTION_LIFETIME: Duration = Duration::from_secs(10);

#[derive(Serialize, Deserialize)]
enum NodeType {
    Client,
    Relay,
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
            route_loop(context.daemon_ctx.clone(), mplex, link_price, false)
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
    // first, we authenticate the other side.
    let neighbor: either::Either<IdentityDescriptor, ClientId> = {
        let mut stream = if is_listen {
            mplex.accept_conn().await?
        } else {
            mplex.open_conn("!init_auth").await?
        };
        // send our own id
        if ctx.init().is_client() {
            let my_id = stdcode::serialize(&ctx.get(MY_CLIENT_ID))?;
            send_message(&my_id, &mut stream).await?;
        } else {
            let my_descriptor = stdcode::serialize(&IdentityDescriptor::new(
                &ctx.get(GLOBAL_IDENTITY)
                    .expect("only relays have global identities"),
                ctx.get(GLOBAL_ONION_SK),
            ))?;
            send_message(&my_descriptor, &mut stream).await?;
        }
        let node_type: NodeType = stdcode::deserialize(&receive_message(&mut stream).await?)?;
        match node_type {
            NodeType::Client => {
                either::Either::Right(stdcode::deserialize(&receive_message(&mut stream).await?)?)
            }
            NodeType::Relay => {
                let relay_descriptor: IdentityDescriptor =
                    stdcode::deserialize(&receive_message(&mut stream).await?)?;
                if relay_descriptor
                    .identity_pk
                    .verify(relay_descriptor.to_sign().as_bytes(), &relay_descriptor.sig)
                    .is_err()
                {
                    anyhow::bail!(
                        "out route authentication for {} failed",
                        relay_descriptor.identity_pk.fingerprint()
                    );
                }
                either::Either::Left(relay_descriptor)
            }
        }
    };

    // then, we start the link maintenance
    let link_channel_and_neigh = neighbor
        .as_ref()
        .map_left(|left| {
            let (send_outgoing, recv_outgoing) = smol::channel::unbounded();
            ctx.get(NEIGH_TABLE_NEW)
                .insert(left.identity_pk.fingerprint(), send_outgoing);
            RelayNeighbor(recv_outgoing, left.identity_pk.fingerprint())
        })
        .map_right(|right| {
            let (send_outgoing, recv_outgoing) = smol::channel::unbounded();
            ctx.get(CLIENT_TABLE).insert(*right, send_outgoing);
            ClientNeighbor(recv_outgoing, *right)
        });
    let link_maintenance = link_maintain(
        LinkContext {
            ctx: ctx.clone(),
            service: Arc::new(LinkService(LinkProtocolImpl {
                ctx: ctx.clone(),
                mplex: mplex.clone(),
                remote: neighbor,
                max_outgoing_price: link_price.max_outgoing_price,
            })),
            mplex,
            neighbor: link_channel_and_neigh,
        },
        is_listen,
    );
    let gossip = todo!();

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
            // let rpc = LinkRpcTransport::new(mplex.clone());
            // let _client = LinkClient::from(rpc);

            let out_route_loop = route_loop(ctx.clone(), mplex, link_price, true);

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

pub async fn send_message<W: AsyncWrite + Unpin>(message: &[u8], mut out: W) -> anyhow::Result<()> {
    let len = (message.len() as u32).to_be_bytes();

    out.write_all(&len).await?;
    out.write_all(message).await?;
    out.flush().await?;

    Ok(())
}

pub async fn receive_message<R: AsyncRead + Unpin>(mut input: R) -> anyhow::Result<Vec<u8>> {
    let mut len = [0; 4];
    input.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len);

    let mut buffer = vec![0; len as usize];
    input.read_exact(&mut buffer).await?;

    Ok(buffer)
}
