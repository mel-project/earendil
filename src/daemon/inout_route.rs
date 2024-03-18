use super::link::LinkMessage;
use crate::{
    config::InRouteConfig,
    context::{DaemonContext, MY_RELAY_IDENTITY, MY_RELAY_ONION_SK},
    daemon::link::Link,
    network,
    pascal::{read_pascal, write_pascal},
};
use crate::{
    config::{ObfsConfig, OutRouteConfig},
    context::MY_CLIENT_ID,
};
use bytes::Bytes;
use earendil_crypt::{ClientId, RelayFingerprint};
use earendil_topology::IdentityDescriptor;
use futures::AsyncReadExt as _;
use nursery_macro::nursery;
use picomux::PicoMux;
use smol::net::{TcpListener, TcpStream};
use stdcode::StdcodeSerializeExt as _;

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

pub async fn dial_out_route(ctx: &DaemonContext, cfg: &OutRouteConfig) -> anyhow::Result<()> {
    let tcp_conn = TcpStream::connect(cfg.connect).await?;
    let (mux, their_client_id, their_relay_descr) = tcp_to_mux(ctx, tcp_conn, &cfg.obfs).await?;
    let link = Link::new_dial(mux).await?;
    manage_mux(ctx, link, their_client_id, their_relay_descr).await
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
            .map(|id| IdentityDescriptor::new(&id, ctx.get(MY_RELAY_ONION_SK)));
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

    // serve linkrpc
    // gossip with the other side by calling their linkrpc
    todo!()
}
