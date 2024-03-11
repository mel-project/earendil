use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use earendil_crypt::{ClientId, RelayFingerprint, RelayIdentityPublic};
use earendil_packet::{RawBody, RawPacket};
use earendil_topology::IdentityDescriptor;
use futures::{AsyncRead, AsyncWrite};
use futures_util::TryFutureExt;
use nursery_macro::nursery;
use rand::Rng;
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
    daemon::{
        context::{DEBTS, GLOBAL_IDENTITY, GLOBAL_ONION_SK, NEIGH_TABLE_NEW, SETTLEMENTS},
        inout_route::{
            chat::{add_client_link, add_relay_link, remove_client_link, remove_relay_link},
            gossip::{
                client_gossip_with_relay_loop, gossip_with_client_loop,
                relay_gossip_with_relay_loop,
            },
        },
        settlement::{
            difficulty_to_micromel, onchain_multiplier, SettlementProof, SettlementRequest,
        },
    },
};

use self::{
    link_connection::{
        client_relay_connection_loop, relay_client_connection_loop, relay_connection_loop,
        LinkProtocolImpl, LinkRpcTransport,
    },
    link_protocol::{LinkClient, LinkService},
};

use super::{
    context::{CLIENT_IDENTITIES, CLIENT_TABLE},
    DaemonContext,
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
        spawn!(in_route_loop(context.daemon_ctx.clone(), mplex, link_price)
            .timeout(CONNECTION_LIFETIME))
        .detach();
    })
}

async fn in_route_loop(
    ctx: DaemonContext,
    mplex: Arc<Multiplex>,
    link_price: LinkPrice,
) -> anyhow::Result<()> {
    let mut stream = mplex.accept_conn().await?;
    let node_type: NodeType = stdcode::deserialize(&receive_message(&mut stream).await?)?;
    let my_descriptor = stdcode::serialize(&IdentityDescriptor::new(
        &ctx.get(GLOBAL_IDENTITY)
            .expect("only relays have global identities"),
        ctx.get(GLOBAL_ONION_SK),
    ))?;

    match node_type {
        NodeType::Client => {
            let client_id: ClientId = stdcode::deserialize(&receive_message(&mut stream).await?)?;

            send_message(&my_descriptor, stream).await?;

            let (send_outgoing, recv_outgoing) = smol::channel::unbounded();
            ctx.get(CLIENT_TABLE).insert(client_id, send_outgoing);

            let service = Arc::new(LinkService(LinkProtocolImpl {
                ctx: ctx.clone(),
                mplex: mplex.clone(),
                remote_client_id: Some(client_id),
                remote_relay_pk: None,
                max_outgoing_price: link_price.max_outgoing_price,
            }));

            relay_client_loop(ctx, mplex, client_id, link_price, service, recv_outgoing).await?;
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

            send_message(&my_descriptor, stream).await?;

            let (send_outgoing, recv_outgoing) = smol::channel::unbounded();
            let service = Arc::new(LinkService(LinkProtocolImpl {
                ctx: ctx.clone(),
                mplex: mplex.clone(),
                remote_client_id: None,
                remote_relay_pk: Some(relay_descriptor.identity_pk),
                max_outgoing_price: link_price.max_outgoing_price,
            }));
            ctx.get(NEIGH_TABLE_NEW)
                .insert(relay_descriptor.identity_pk.fingerprint(), send_outgoing);

            relay_loop(
                ctx,
                mplex,
                relay_descriptor.identity_pk,
                link_price,
                service,
                recv_outgoing,
            )
            .await?;
        }
    }

    Ok(())
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

            let out_route_loop =
                out_route_loop(ctx.clone(), mplex, context.remote_fingerprint, link_price);

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

async fn out_route_loop(
    ctx: DaemonContext,
    mplex: Arc<Multiplex>,
    their_fp: RelayFingerprint,
    link_price: LinkPrice,
) -> anyhow::Result<()> {
    let mut stream = mplex.open_conn("!init_auth").await?;
    let i_am_client = ctx.init().in_routes.is_empty();
    let my_id = rand::thread_rng().gen::<ClientId>();

    if i_am_client {
        let msg = stdcode::serialize(&NodeType::Client)?;
        send_message(&msg, &mut stream).await?;

        let my_id = stdcode::serialize(&my_id)?;
        send_message(&my_id, &mut stream).await?;
    } else {
        let msg = stdcode::serialize(&NodeType::Relay)?;
        send_message(&msg, &mut stream).await?;

        let my_descriptor = stdcode::serialize(&IdentityDescriptor::new(
            &ctx.get(GLOBAL_IDENTITY)
                .expect("only relays have global identities"),
            ctx.get(GLOBAL_ONION_SK),
        ))?;
        send_message(&my_descriptor, &mut stream).await?;
    };

    let res = receive_message(stream).await?;
    let their_descriptor: IdentityDescriptor = stdcode::deserialize(&res)?;
    let their_pk = their_descriptor.identity_pk;

    if their_pk.fingerprint() != their_fp {
        anyhow::bail!(
            "neighbor fingerprint {} different from configured {}",
            their_pk.fingerprint(),
            their_fp
        )
    }
    if their_pk
        .verify(their_descriptor.to_sign().as_bytes(), &their_descriptor.sig)
        .is_err()
    {
        anyhow::bail!(
            "out route authentication for {} failed",
            their_descriptor.identity_pk.fingerprint()
        );
    }

    let (send_outgoing, recv_outgoing) = smol::channel::unbounded();
    let service = Arc::new(LinkService(LinkProtocolImpl {
        ctx: ctx.clone(),
        mplex: mplex.clone(),
        remote_client_id: None,
        remote_relay_pk: Some(their_descriptor.identity_pk),
        max_outgoing_price: link_price.max_outgoing_price,
    }));

    // register the outgoing channel. This registration eventually expires, but we'll die before that so it's fine.
    // Note that this will overwrite any existing entry, which will close their send_outgoing, which will stop their loop. That is a good thing!
    ctx.get(NEIGH_TABLE_NEW).insert(their_fp, send_outgoing);

    if i_am_client {
        ctx.get(CLIENT_IDENTITIES).insert(their_fp, my_id);

        client_relay_loop(ctx, mplex, their_pk, link_price, service, recv_outgoing).await?;
    } else {
        relay_loop(ctx, mplex, their_pk, link_price, service, recv_outgoing).await?;
    }

    Ok(())
}

async fn relay_loop(
    ctx: DaemonContext,
    mplex: Arc<Multiplex>,
    their_pk: RelayIdentityPublic,
    link_price: LinkPrice,
    service: Arc<LinkService<LinkProtocolImpl>>,
    recv_outgoing: Receiver<(RawPacket, RelayFingerprint)>,
) -> anyhow::Result<()> {
    let connection_loop = relay_connection_loop(service, mplex.clone(), recv_outgoing);

    connection_loop
        .race(async move {
            let gossip_loop = {
                let rpc = LinkRpcTransport::new(mplex.clone());
                let client = LinkClient::from(rpc);
                relay_gossip_with_relay_loop(ctx.clone(), their_pk, client)
            };

            let rpc = LinkRpcTransport::new(mplex.clone());
            let client = Arc::new(LinkClient::from(rpc));

            // add link client to chats mapping and deregister when out of scope
            add_relay_link(&ctx, their_pk.fingerprint(), client.clone());
            scopeguard::defer!({
                remove_relay_link(&ctx, &their_pk.fingerprint());
            });

            let price_loop = async {
                loop {
                    ctx.get(DEBTS).insert_relay_incoming_price(
                        their_pk.fingerprint(),
                        link_price.incoming_price,
                        link_price.incoming_debt_limit,
                    );
                    // attempt to push the price
                    if link_price.incoming_price > 0 {
                        client
                            .relay_push_price(
                                link_price.incoming_price,
                                link_price.incoming_debt_limit,
                            )
                            .timeout(Duration::from_secs(60))
                            .await
                            .context("push_price timed out")??;
                    }
                    smol::Timer::after(Duration::from_secs(300)).await;
                }
            };

            // include auto_settle_loop if we have provided automatic settlement options in the config
            if let Some(AutoSettle { interval }) = ctx.get(SETTLEMENTS).auto_settle {
                let auto_settle_loop = async {
                    loop {
                        tracing::debug!("starting auto_settle loop!");
                        smol::Timer::after(Duration::from_secs(interval)).await;

                        let seed = client.request_seed().await?;
                        tracing::debug!("got an auto_settle seed");
                        let debts = ctx.get(DEBTS);
                        let net_debt = debts
                            .relay_net_debt_est(&their_pk.fingerprint())
                            .unwrap_or_default();
                        if net_debt.is_negative() {
                            let i_owe = net_debt.unsigned_abs() as u64;
                            let difficulty = (i_owe / onchain_multiplier()).ilog2() as usize;

                            if difficulty > 0 {
                                let difficulty = if difficulty > 64 { 64 } else { difficulty };
                                let proof = SettlementProof::new_auto(seed, difficulty);
                                let request = SettlementRequest::new(
                                    ctx.get(GLOBAL_IDENTITY)
                                        .expect("only relays have global identities"),
                                    difficulty_to_micromel(difficulty),
                                    proof,
                                );
                                match client.start_settlement(request).await {
                                    Ok(Some(_)) => log::debug!(
                                        "automatic settlement of {} micromel accepted by {}",
                                        difficulty_to_micromel(difficulty),
                                        their_pk.fingerprint()
                                    ),
                                    Ok(None) => {
                                        log::warn!(
                                            "automatic settlement rejected by {}",
                                            their_pk.fingerprint(),
                                        )
                                    }
                                    Err(e) => log::warn!(
                                        "error with automatic settlement sent to {}: {e}",
                                        their_pk.fingerprint()
                                    ),
                                }
                            }
                        }
                    }
                };

                gossip_loop.race(price_loop.race(auto_settle_loop)).await
            } else {
                gossip_loop.race(price_loop).await
            }
        })
        .await?;

    Ok(())
}

async fn client_relay_loop(
    ctx: DaemonContext,
    mplex: Arc<Multiplex>,
    their_pk: RelayIdentityPublic,
    link_price: LinkPrice,
    service: Arc<LinkService<LinkProtocolImpl>>,
    recv_outgoing: Receiver<(RawPacket, RelayFingerprint)>,
) -> anyhow::Result<()> {
    let connection_loop = client_relay_connection_loop(service, mplex.clone(), recv_outgoing);

    connection_loop
        .race(async move {
            let gossip_loop = {
                let rpc = LinkRpcTransport::new(mplex.clone());
                let client = LinkClient::from(rpc);
                client_gossip_with_relay_loop(ctx.clone(), their_pk, client)
            };

            let rpc = LinkRpcTransport::new(mplex.clone());
            let link = Arc::new(LinkClient::from(rpc));

            // add link client to chats mapping and deregister when out of scope
            add_relay_link(&ctx, their_pk.fingerprint(), link.clone());
            scopeguard::defer!({
                remove_relay_link(&ctx, &their_pk.fingerprint());
            });

            let price_loop = async {
                loop {
                    ctx.get(DEBTS).insert_relay_incoming_price(
                        their_pk.fingerprint(),
                        link_price.incoming_price,
                        link_price.incoming_debt_limit,
                    );
                    // attempt to push the price
                    if link_price.incoming_price > 0 {
                        link.client_push_price(
                            link_price.incoming_price,
                            link_price.incoming_debt_limit,
                        )
                        .timeout(Duration::from_secs(60))
                        .await
                        .context("push_price timed out")??;
                    }
                    smol::Timer::after(Duration::from_secs(300)).await;
                }
            };

            // include auto_settle_loop if we have provided automatic settlement options in the config
            if let Some(AutoSettle { interval }) = ctx.get(SETTLEMENTS).auto_settle {
                let auto_settle_loop = async {
                    loop {
                        tracing::debug!("starting auto_settle loop!");
                        smol::Timer::after(Duration::from_secs(interval)).await;

                        let seed = link.request_seed().await?;
                        tracing::debug!("got an auto_settle seed");
                        let debts = ctx.get(DEBTS);
                        let net_debt = debts
                            .relay_net_debt_est(&their_pk.fingerprint())
                            .unwrap_or_default();
                        if net_debt.is_negative() {
                            let i_owe = net_debt.unsigned_abs() as u64;
                            let difficulty = (i_owe / onchain_multiplier()).ilog2() as usize;

                            if difficulty > 0 {
                                let difficulty = if difficulty > 64 { 64 } else { difficulty };
                                let proof = SettlementProof::new_auto(seed, difficulty);
                                let request = SettlementRequest::new(
                                    ctx.get(GLOBAL_IDENTITY)
                                        .expect("only relays have global identities"),
                                    difficulty_to_micromel(difficulty),
                                    proof,
                                );
                                match link.start_settlement(request).await {
                                    Ok(Some(_)) => log::debug!(
                                        "automatic settlement of {} micromel accepted by {}",
                                        difficulty_to_micromel(difficulty),
                                        their_pk.fingerprint()
                                    ),
                                    Ok(None) => {
                                        log::warn!(
                                            "automatic settlement rejected by {}",
                                            their_pk.fingerprint(),
                                        )
                                    }
                                    Err(e) => log::warn!(
                                        "error with automatic settlement sent to {}: {e}",
                                        their_pk.fingerprint()
                                    ),
                                }
                            }
                        }
                    }
                };

                gossip_loop.race(price_loop.race(auto_settle_loop)).await
            } else {
                gossip_loop.race(price_loop).await
            }
        })
        .await?;

    Ok(())
}

async fn relay_client_loop(
    ctx: DaemonContext,
    mplex: Arc<Multiplex>,
    their_id: ClientId,
    link_price: LinkPrice,
    service: Arc<LinkService<LinkProtocolImpl>>,
    recv_outgoing: Receiver<(RawBody, u64)>,
) -> anyhow::Result<()> {
    let connection_loop = relay_client_connection_loop(service, mplex.clone(), recv_outgoing);

    connection_loop
        .race(async move {
            let gossip_loop = {
                let rpc = LinkRpcTransport::new(mplex.clone());
                let client = LinkClient::from(rpc);
                gossip_with_client_loop(ctx.clone(), their_id, client)
            };

            let rpc = LinkRpcTransport::new(mplex.clone());
            let client = Arc::new(LinkClient::from(rpc));

            // add link client to chats mapping and deregister when out of scope
            add_client_link(&ctx, their_id, client.clone());
            scopeguard::defer!({
                remove_client_link(&ctx, &their_id);
            });

            let price_loop = async {
                loop {
                    ctx.get(DEBTS).insert_client_incoming_price(
                        their_id,
                        link_price.incoming_price,
                        link_price.incoming_debt_limit,
                    );
                    // attempt to push the price
                    if link_price.incoming_price > 0 {
                        client
                            .relay_push_price(
                                link_price.incoming_price,
                                link_price.incoming_debt_limit,
                            )
                            .timeout(Duration::from_secs(60))
                            .await
                            .context("push_price timed out")??;
                    }
                    smol::Timer::after(Duration::from_secs(300)).await;
                }
            };

            // include auto_settle_loop if we have provided automatic settlement options in the config
            if let Some(AutoSettle { interval }) = ctx.get(SETTLEMENTS).auto_settle {
                let auto_settle_loop = async {
                    loop {
                        tracing::debug!("starting auto_settle loop!");
                        smol::Timer::after(Duration::from_secs(interval)).await;

                        let seed = client.request_seed().await?;
                        tracing::debug!("got an auto_settle seed");
                        let debts = ctx.get(DEBTS);
                        let net_debt = debts.client_net_debt_est(&their_id).unwrap_or_default();
                        if net_debt.is_negative() {
                            let i_owe = net_debt.unsigned_abs() as u64;
                            let difficulty = (i_owe / onchain_multiplier()).ilog2() as usize;

                            if difficulty > 0 {
                                let difficulty = if difficulty > 64 { 64 } else { difficulty };
                                let proof = SettlementProof::new_auto(seed, difficulty);
                                let request = SettlementRequest::new(
                                    ctx.get(GLOBAL_IDENTITY)
                                        .expect("only relays have global identities"),
                                    difficulty_to_micromel(difficulty),
                                    proof,
                                );
                                match client.start_settlement(request).await {
                                    Ok(Some(_)) => log::debug!(
                                        "automatic settlement of {} micromel accepted by {}",
                                        difficulty_to_micromel(difficulty),
                                        their_id
                                    ),
                                    Ok(None) => {
                                        log::warn!("automatic settlement rejected by {}", their_id)
                                    }
                                    Err(e) => log::warn!(
                                        "error with automatic settlement sent to {}: {e}",
                                        their_id
                                    ),
                                }
                            }
                        }
                    }
                };

                gossip_loop.race(price_loop.race(auto_settle_loop)).await
            } else {
                gossip_loop.race(price_loop).await
            }
        })
        .await?;

    Ok(())
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
