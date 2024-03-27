use std::time::Duration;

use self::{gossip::gossip_once, link_protocol::LinkService};

use super::link::LinkMessage;
use crate::{
    config::InRouteConfig,
    context::{DaemonContext, MY_RELAY_IDENTITY, MY_RELAY_ONION_SK, RELAY_GRAPH},
    daemon::{chat::CHATS, inout_route::link_protocol::LinkClient, link::Link},
    n2r, network,
    pascal::{read_pascal, write_pascal},
};
use crate::{
    config::{ObfsConfig, OutRouteConfig},
    context::MY_CLIENT_ID,
};
use anyhow::Context;
use bytes::Bytes;
use earendil_crypt::ClientId;
use earendil_packet::{RawBody, RawPacket};
use earendil_topology::IdentityDescriptor;
use futures::AsyncReadExt as _;
use nursery_macro::nursery;
use picomux::PicoMux;
use smol::{
    future::FutureExt,
    net::{TcpListener, TcpStream},
};
use stdcode::StdcodeSerializeExt as _;

mod gossip;
mod link_protocol;
mod link_protocol_impl;

/*
Links aren't inherently client-relay or relay-relay.

Instead, each link is logically either a client-relay link, or it is *also* a relay-relay link.

Basically, the dialing side may or may not have a relay identity. The listening side always does.

This means that the link-maintaining code *always* calls subscribe_outgoing_client. It *may* call subscribe_outgoing_relay if the other side is a relay.

Relay and client messages are then put on the same link.
*/

#[tracing::instrument(skip_all, fields(listen=debug(cfg.listen)))]
pub async fn listen_in_route(ctx: &DaemonContext, cfg: &InRouteConfig) -> anyhow::Result<()> {
    let listener = TcpListener::bind(cfg.listen).await?;
    nursery!(loop {
        let (tcp_conn, remote_addr) = listener.accept().await?;
        tracing::debug!(
            remote_addr = debug(remote_addr),
            "accepted a TCP connection"
        );

        spawn!(async move {
            let (mux, their_client_id, their_relay_descr) =
                tcp_to_mux(ctx, tcp_conn, &cfg.obfs).await?;
            let link = Link::new_listen(mux).await?;
            manage_mux(ctx, link, their_client_id, their_relay_descr).await
        })
        .detach();
    })
}

#[tracing::instrument(skip_all, fields(connect=debug(cfg.connect)))]
pub async fn dial_out_route(ctx: &DaemonContext, cfg: &OutRouteConfig) -> anyhow::Result<()> {
    loop {
        let fallible = async {
            let tcp_conn = TcpStream::connect(cfg.connect).await?;
            tracing::debug!("TCP connected to other side");
            let (mux, their_client_id, their_relay_descr) =
                tcp_to_mux(ctx, tcp_conn, &cfg.obfs).await?;
            let link = Link::new_dial(mux).await?;
            tracing::debug!("link connected to other side");
            manage_mux(ctx, link, their_client_id, their_relay_descr).await?;
            anyhow::Ok(())
        };
        if let Err(err) = fallible.await {
            tracing::warn!(
                err = debug(err),
                connect = debug(cfg.connect),
                "restarting out route"
            );
        }
        smol::Timer::after(Duration::from_secs(1)).await;
    }
}

async fn tcp_to_mux(
    ctx: &DaemonContext,
    tcp_stream: TcpStream,
    obfs_cfg: &ObfsConfig,
) -> anyhow::Result<(PicoMux, ClientId, Option<IdentityDescriptor>)> {
    let obfsed_conn = match &obfs_cfg {
        ObfsConfig::None => tcp_stream,
    };
    let (mut read, mut write) = obfsed_conn.split();

    let send_auth = async {
        let my_client_id = *ctx.get(MY_CLIENT_ID);
        let my_relay_descr = ctx
            .get(MY_RELAY_IDENTITY)
            .as_ref()
            .map(|id| IdentityDescriptor::new(id, ctx.get(MY_RELAY_ONION_SK)));
        let auth_msg = (my_client_id, my_relay_descr).stdcode();
        write_pascal(&auth_msg, &mut write).await?;
        anyhow::Ok(())
    };

    let recv_auth = async {
        let bts = read_pascal(&mut read).await?;
        let (their_client_id, their_relay_descr): (ClientId, Option<IdentityDescriptor>) =
            stdcode::deserialize(&bts)?;
        anyhow::Ok((their_client_id, their_relay_descr))
    };

    let (a, b) = futures::join!(send_auth, recv_auth);
    a?;
    let (their_client_id, their_relay_descr) = b?;
    let mux = PicoMux::new(read, write);
    Ok((mux, their_client_id, their_relay_descr))
}

async fn manage_mux(
    ctx: &DaemonContext,
    link: Link,
    their_client_id: ClientId,
    their_relay_descr: Option<IdentityDescriptor>,
) -> anyhow::Result<()> {
    scopeguard::defer!(tracing::debug!("manage_mux died"));

    if let Some(descr) = their_relay_descr.as_ref() {
        ctx.get(RELAY_GRAPH)
            .write()
            .insert_identity(descr.clone())?;
    }
    // subscribe to the right outgoing stuff and stuff them into the link
    let recv_outgoing_client = network::subscribe_outgoing_client(ctx, their_client_id);
    let send_outgoing_client = async {
        loop {
            let msg = recv_outgoing_client.recv().await?;
            link.send_msg(LinkMessage::ToClient {
                body: Bytes::copy_from_slice(&msg.0),
                rb_id: msg.1,
            })
            .await?;
        }
    };

    let send_outgoing_relay = async {
        if let Some(relay_descr) = their_relay_descr.as_ref() {
            let recv_relay_msg =
                network::subscribe_outgoing_relay(ctx, relay_descr.identity_pk.fingerprint());
            loop {
                let (pkt, next_peeler) = recv_relay_msg.recv().await?;
                link.send_msg(LinkMessage::ToRelay {
                    packet: Bytes::copy_from_slice(bytemuck::bytes_of(&pkt)),
                    next_peeler,
                })
                .await?;
            }
        } else {
            smol::future::pending().await
        }
    };

    let recv_incoming = async {
        loop {
            let in_msg = link.recv_msg().await?;
            match in_msg {
                LinkMessage::ToClient { body, rb_id } => {
                    tracing::trace!(rb_id, "incoming ToClient");
                    let body: RawBody = *bytemuck::try_from_bytes(&body)
                        .ok()
                        .context("failed to deserialize incoming RawBody")?;
                    if let Err(err) = n2r::incoming_backward(ctx, body, rb_id).await {
                        tracing::debug!(err = debug(err), "failed to process incoming backward");
                    }
                }
                LinkMessage::ToRelay {
                    packet,
                    next_peeler,
                } => {
                    tracing::trace!(next_peeler = debug(next_peeler), "incoming ToRelay");
                    let pkt: RawPacket = *bytemuck::try_from_bytes(&packet)
                        .ok()
                        .context("failed to deserialize incoming RawPacket")?;
                    if let Err(err) = network::incoming_raw(ctx, next_peeler, pkt).await {
                        tracing::debug!(err = debug(err), "failed to process incoming raw");
                    }
                }
            }
        }
    };

    // rpc
    let remote_relay_fp = their_relay_descr
        .as_ref()
        .map(|desc| desc.identity_pk.fingerprint());
    let service = LinkService(link_protocol_impl::LinkProtocolImpl {
        ctx: ctx.clone(),
        remote_client_id: their_client_id,
        remote_relay_fp,
    });
    let rpc_serve = link.rpc_serve(service);

    // gossip
    let gossip_loop = async {
        loop {
            let _ = gossip_once(ctx, &link, remote_relay_fp).await;
            smol::Timer::after(Duration::from_secs(1)).await;
        }
    };

    // chat
    let chat_loop = async {
        loop {
            let unsent = ctx
                .get(CHATS)
                .wait_unsent(
                    their_relay_descr
                        .as_ref()
                        .map(|r| either::Either::Right(r.identity_pk.fingerprint()))
                        .unwrap_or_else(|| either::Either::Left(their_client_id)),
                )
                .await;
            tracing::debug!(len = unsent.len(), "sending batch of chats");
            for unsent in unsent {
                tracing::debug!(text = &unsent.text, "sending a chat");
                LinkClient(link.rpc_transport())
                    .push_chat(unsent.text)
                    .await?;
            }
        }
    };

    send_outgoing_client
        .race(send_outgoing_relay)
        .race(rpc_serve)
        .race(gossip_loop)
        .race(recv_incoming)
        .race(chat_loop)
        .await
}
