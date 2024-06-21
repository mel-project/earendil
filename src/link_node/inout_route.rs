use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use earendil_topology::IdentityDescriptor;
use futures::AsyncReadExt;
use picomux::PicoMux;
use serde::{Deserialize, Serialize};
use sillad::{
    dialer::Dialer as _,
    listener::Listener,
    tcp::{TcpDialer, TcpListener},
    Pipe,
};

use smol::{channel::Sender, future::FutureExt};
use stdcode::StdcodeSerializeExt;

use crate::{
    config::{InRouteConfig, ObfsConfig, OutRouteConfig, PriceConfig},
    pascal::{read_pascal, write_pascal},
    DebtEntry,
};

use super::{
    gossip::gossip_once,
    link::{Link, LinkMessage},
    link_protocol::LinkService,
    link_protocol_impl::LinkProtocolImpl,
    types::{ClientId, LinkNodeCtx, LinkNodeId, LinkPaymentInfo, NeighborId},
};

pub(super) async fn process_in_route(
    link_node_ctx: LinkNodeCtx,
    name: &str,
    in_route: &InRouteConfig,
    send_raw: Sender<LinkMessage>,
) -> anyhow::Result<()> {
    let mut listener = TcpListener::bind(in_route.listen).await?;
    match &in_route.obfs {
        ObfsConfig::None => loop {
            let pipe = listener.accept().await?;
            tracing::debug!(
                name,
                remote_addr = debug(pipe.remote_addr()),
                "accepted a TCP connection"
            );
            smolscale::spawn(handle_pipe(
                link_node_ctx.clone(),
                pipe,
                send_raw.clone(),
                RouteConfig::In(in_route.clone()),
            ))
            .detach();
        },
        ObfsConfig::Sosistab3(_) => todo!(),
    }
}

pub(super) async fn process_out_route(
    link_node_ctx: LinkNodeCtx,
    name: &str,
    out_route: &OutRouteConfig,
    send_raw: Sender<LinkMessage>,
) -> anyhow::Result<()> {
    loop {
        let fallible = async {
            let dest_addr = if let Ok(socket_addr) = out_route.connect.parse() {
                socket_addr
            } else {
                let addrs: Vec<SocketAddr> = out_route
                    .connect
                    .clone()
                    .to_socket_addrs()
                    .map(|iter| iter.collect())
                    .map_err(|e| {
                        anyhow::anyhow!("unable to resolve domain {}: {}", &out_route.connect, e)
                    })?;
                let addr = addrs.first().context("empty list of resolved domains")?;

                *addr
            };
            let tcp_dialer = TcpDialer { dest_addr };
            match &out_route.obfs {
                ObfsConfig::None => {
                    let tcp_pipe = tcp_dialer.dial().await?;
                    tracing::debug!(name, "TCP connected to other side");
                    handle_pipe(
                        link_node_ctx.clone(),
                        tcp_pipe,
                        send_raw.clone(),
                        RouteConfig::Out(out_route.clone()),
                    )
                    .await
                }
                ObfsConfig::Sosistab3(_cookie) => {
                    todo!()
                }
            }
        };
        if let Err(err) = fallible.await {
            tracing::warn!(
                err = debug(err),
                connect = debug(&out_route.connect),
                "restarting out route"
            );
        }
        smol::Timer::after(Duration::from_secs(1)).await;
    }
}

#[derive(Clone)]
enum RouteConfig {
    Out(OutRouteConfig),
    In(InRouteConfig),
}

async fn handle_pipe(
    link_node_ctx: LinkNodeCtx,
    pipe: impl Pipe,
    send_raw: Sender<LinkMessage>,
    route_config: RouteConfig,
) -> anyhow::Result<()> {
    let (link, their_descr, payment_info, price_config) = match route_config.clone() {
        RouteConfig::Out(config) => {
            let (mux, their_descr, payment_info) =
                pipe_to_mux(&link_node_ctx, pipe, config.price_config.clone()).await?;
            (
                Arc::new(Link::new_dial(mux).await?),
                their_descr,
                payment_info,
                config.price_config,
            )
        }
        RouteConfig::In(config) => {
            let (mux, their_descr, payment_info) =
                pipe_to_mux(&link_node_ctx, pipe, config.price_config.clone()).await?;
            (
                Arc::new(Link::new_listen(mux).await?),
                their_descr,
                payment_info,
                config.price_config,
            )
        }
    };

    // insert as either client or relay
    match their_descr.clone() {
        LinkNodeDescr::Relay(descr) => link_node_ctx.link_table.insert(
            NeighborId::Relay(descr.identity_pk.fingerprint()),
            (link.clone(), payment_info),
        ),
        LinkNodeDescr::Client(id) => link_node_ctx
            .link_table
            .insert(NeighborId::Client(id), (link.clone(), payment_info)),
    };

    let their_relay_fp = match their_descr.clone() {
        LinkNodeDescr::Relay(descr) => Some(descr.identity_pk.fingerprint()),
        LinkNodeDescr::Client(_) => None,
    };

    let their_id = match their_descr {
        LinkNodeDescr::Relay(descr) => NeighborId::Relay(descr.identity_pk.fingerprint()),
        LinkNodeDescr::Client(id) => NeighborId::Client(id),
    };

    let gossip_loop = async {
        loop {
            smol::Timer::after(Duration::from_secs(1)).await;
            if let Err(e) = gossip_once(&link_node_ctx, &link, their_relay_fp).await {
                tracing::warn!(err = debug(e), "gossip_once failed");
            };
        }
    };

    let rpc_serve_loop = link.rpc_serve(LinkService(LinkProtocolImpl {
        ctx: link_node_ctx.clone(),
        remote_id: their_id,
    }));

    let pkt_fwd_loop = async {
        // pull messages from the link & forward into LinkNode
        loop {
            let msg = link.recv_msg().await?;
            tracing::trace!("received LinkMessage from {:?}", their_id);
            let debt = link_node_ctx.store.get_debt(their_id).await?;
            tracing::debug!(
                "downstream's CURR_DEBT = {debt}, debt_limit={}",
                price_config.inbound_debt_limit
            );
            if debt < -price_config.inbound_debt_limit {
                tracing::warn!(
                    "DROPPING PACKET: {:?} is over their debt limit! debt={debt}; debt_limit={}",
                    their_id,
                    price_config.inbound_debt_limit
                );
                continue;
            };
            // increment remote's debt
            link_node_ctx
                .store
                .insert_debt_entry(
                    their_id,
                    DebtEntry {
                        delta: -price_config.inbound_price,
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("Time went backwards")
                            .as_secs(),
                        proof: None,
                    },
                )
                .await?;
            send_raw.send(msg).await?;
        }
    };

    gossip_loop.race(rpc_serve_loop).race(pkt_fwd_loop).await
}

#[derive(Serialize, Deserialize, Debug, Clone)]
enum LinkNodeDescr {
    Relay(IdentityDescriptor),
    Client(ClientId),
}

async fn pipe_to_mux(
    link_node_ctx: &LinkNodeCtx,
    pipe: impl Pipe,
    price_config: PriceConfig,
) -> anyhow::Result<(PicoMux, LinkNodeDescr, LinkPaymentInfo)> {
    let (mut read, mut write) = pipe.split();
    let send_auth = async {
        let my_descr = match link_node_ctx.my_id {
            LinkNodeId::Relay(id) => {
                LinkNodeDescr::Relay(IdentityDescriptor::new(&id, &link_node_ctx.my_onion_sk))
            }
            LinkNodeId::Client(id) => LinkNodeDescr::Client(id),
        };
        let my_payment_info = LinkPaymentInfo {
            price: price_config.inbound_price,
            debt_limit: price_config.inbound_debt_limit,
            paysystem_name_addrs: link_node_ctx.payment_systems.get_available(),
        };
        let auth_msg = (my_descr, my_payment_info).stdcode();
        write_pascal(&auth_msg, &mut write).await?;
        anyhow::Ok(())
    };

    let recv_auth = async {
        let bts = read_pascal(&mut read).await?;
        let (their_descr, their_payinfo): (LinkNodeDescr, LinkPaymentInfo) =
            stdcode::deserialize(&bts)?;
        tracing::debug!(
            "their_price: {}; our_max_price: {}",
            their_payinfo.price,
            price_config.outbound_max_price
        );
        if their_payinfo.price > price_config.outbound_max_price {
            anyhow::bail!("{:?} price too high!", their_descr)
        };
        if their_payinfo.debt_limit < price_config.outbound_min_debt_limit {
            anyhow::bail!(
                "{:?} debt limit too low = asking for too much prepayment!",
                their_descr
            )
        };
        if link_node_ctx
            .payment_systems
            .select(&their_payinfo.paysystem_name_addrs)
            .is_none()
        {
            anyhow::bail!("{:?} no supported payment methods", their_descr)
        };
        anyhow::Ok((their_descr, their_payinfo))
    };

    let (a, b) = futures::join!(send_auth, recv_auth);
    a?;
    let (their_descr, their_payinfo) = b?;
    let mux = PicoMux::new(read, write);
    Ok((mux, their_descr, their_payinfo))
}
