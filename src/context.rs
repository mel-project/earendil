use earendil_crypt::{ClientId, RelayIdentitySecret};
use earendil_packet::crypt::DhSecret;
use earendil_topology::RelayGraph;

use parking_lot::RwLock;
use stdcode::{deserialize, StdcodeSerializeExt};

use crate::{
    config::ConfigFile,
    db::{db_read, db_write},
    debts::Debts,
};

pub type DaemonContext = anyctx::AnyCtx<ConfigFile>;
pub type CtxField<T> = fn(&DaemonContext) -> T;

pub static MY_RELAY_IDENTITY: CtxField<Option<RelayIdentitySecret>> = |ctx| {
    tracing::debug!("INITIALIZING GLOBAL IDENTITY");
    ctx.init().identity.as_ref().map(|id| {
        id.actualize_relay()
            .expect("failed to initialize global identity")
    })
};

pub static MY_RELAY_ONION_SK: CtxField<DhSecret> = |_| DhSecret::generate();
pub static RELAY_GRAPH: CtxField<RwLock<RelayGraph>> = |ctx| {
    let ctx = ctx.clone();
    smol::future::block_on(async move {
        match db_read(&ctx, "relay_graph")
            .await
            .ok()
            .flatten()
            .and_then(|s| stdcode::deserialize(&s).ok())
        {
            Some(g) => RwLock::new(g),
            None => {
                tracing::debug!("**** INIT RELAY GRAPH****");
                RwLock::new(RelayGraph::new())
            }
        }
    })
};

pub static DEBTS: CtxField<Debts> = |ctx| {
    smol::future::block_on(async move {
        match db_read(ctx, "debts").await {
            Ok(Some(debts)) => {
                tracing::debug!("retrieving persisted debts");
                match Debts::from_bytes(debts) {
                    Ok(debts) => debts,
                    Err(e) => {
                        tracing::warn!("debt decode error: {e}");
                        Debts::new()
                    }
                }
            }
            _ => {
                tracing::debug!("initializing debts");
                Debts::new()
            }
        }
    })
};

pub static MY_CLIENT_ID: CtxField<ClientId> = |ctx| {
    smol::future::block_on(async {
        match db_read(ctx, "client_id").await {
            Ok(Some(id)) => {
                let client_id = deserialize(&id).unwrap_or(generate_client_id(ctx).await);
                tracing::debug!("retrieved client id {client_id}");
                client_id
            }
            Ok(None) => generate_client_id(ctx).await,
            Err(e) => {
                tracing::warn!("error retrieving client id: {e}");
                generate_client_id(ctx).await
            }
        }
    })
};

async fn generate_client_id(ctx: &DaemonContext) -> ClientId {
    let id = rand::random::<u64>() / 100000 * 100000;
    tracing::debug!("generated new client id: {id}");

    if let Err(e) = db_write(ctx, "client_id", id.stdcode()).await {
        tracing::warn!("error saving client id: {e}");
    }

    id
}
