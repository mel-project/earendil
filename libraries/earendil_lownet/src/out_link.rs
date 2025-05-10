use async_stdcode::{StdcodeReader, StdcodeWriter};
use clone_macro::clone;
use haiyuu::{Handle, Process};
use std::sync::{Arc, RwLock};

use futures_util::AsyncReadExt;
use picomux::{PicoMux, Stream};
use sillad::dialer::{Dialer, DialerExt};

use crate::{
    NodeAddr, NodeIdentity, OutLinkConfig, auth::AddrAssignment, link::Link, link_table::LinkTable,
    router::Router,
};

pub async fn out_link(secret: NodeIdentity, cfg: OutLinkConfig) {}

async fn out_link_once(
    secret: NodeIdentity,
    cfg: &OutLinkConfig,
    table: Arc<RwLock<LinkTable>>,
    router: Handle<Router>,
) -> anyhow::Result<()> {
    let res = async_net::resolve(&cfg.connect).await?;
    tracing::debug!(
        connect = display(&cfg.connect),
        res = debug(&res),
        "DNS resolved"
    );

    let conn = match &cfg.obfs {
        crate::ObfsConfig::None => sillad::tcp::HappyEyeballsTcpDialer(res).dial().await?,
        crate::ObfsConfig::Sosistab3(cookie) => {
            sillad_sosistab3::dialer::SosistabDialer {
                inner: sillad::tcp::HappyEyeballsTcpDialer(res),
                cookie: sillad_sosistab3::Cookie::new(cookie),
            }
            .dynamic()
            .dial()
            .await?
        }
    };
    tracing::debug!(
        connect = display(&cfg.connect),
        obfs = debug(&cfg.obfs),
        "pipe dialed"
    );

    // start the picomux session
    let (read, write) = conn.split();
    let mux = PicoMux::new(read, write);
    let auth = mux.open(b"auth").await?;
    let assignment = out_link_auth(secret, auth).await?;
    let local_addr = match secret {
        NodeIdentity::Relay(relay_identity_secret) => NodeAddr {
            relay: relay_identity_secret.public().fingerprint(),
            client_id: 0,
        },
        NodeIdentity::ClientBearer(_) => NodeAddr {
            relay: cfg.fingerprint,
            client_id: assignment.client_id,
        },
    };

    // create Link and insert into the table
    let link_id = LinkTable::next_id();
    let (send_death, recv_death) = oneshot::channel();
    let on_drop = clone!([table], move || {
        table.write().unwrap().remove(link_id);
        let _ = send_death.send(());
    });
    let link = Link {
        pipe: Box::new(mux.open(b"link").await?),
        router: router.downgrade(),
        on_drop: Box::new(on_drop),
    }
    .spawn_smolscale();
    table.write().unwrap().insert(
        local_addr,
        NodeAddr {
            relay: cfg.fingerprint,
            client_id: 0,
        },
        link_id,
        link,
    );
    let _ = recv_death.await;
    Ok(())
}

async fn out_link_auth(secret: NodeIdentity, auth: Stream) -> anyhow::Result<AddrAssignment> {
    let (down, up) = auth.split();
    let mut down = StdcodeReader::new(down);
    let mut up = StdcodeWriter::new(up);
    // indicate our ID to the other end
    match secret {
        NodeIdentity::Relay(relay_identity_secret) => {
            up.write(0u128).await?;
            up.write(relay_identity_secret.public()).await?;
        }
        NodeIdentity::ClientBearer(id) => {
            up.write(id).await?;
        }
    }
    // read a string for the confirmation
    let resp: Option<String> = down.read().await?;
    if let Some(resp) = resp {
        anyhow::bail!("out link rejected: {resp}")
    }
    // now it's time for the assignment
    let assignment: AddrAssignment = down.read().await?;
    Ok(assignment)
}
