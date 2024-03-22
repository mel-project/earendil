use earendil_crypt::{ClientId, RelayIdentitySecret};
use earendil_packet::crypt::OnionSecret;
use earendil_topology::RelayGraph;

use parking_lot::RwLock;

use crate::{config::ConfigFile, db::db_read, debts::Debts, settlement::Settlements};

pub type DaemonContext = anyctx::AnyCtx<ConfigFile>;
pub type CtxField<T> = fn(&DaemonContext) -> T;

pub static MY_RELAY_IDENTITY: CtxField<Option<RelayIdentitySecret>> = |ctx| {
    tracing::debug!("INITIALIZING GLOBAL IDENTITY");
    ctx.init().identity.as_ref().map(|id| {
        id.actualize_relay()
            .expect("failed to initialize global identity")
    })
};

pub static MY_RELAY_ONION_SK: CtxField<OnionSecret> = |_| OnionSecret::generate();
pub static RELAY_GRAPH: CtxField<RwLock<RelayGraph>> = |ctx| {
    let ctx = ctx.clone();
    smol::future::block_on(async move {
        tracing::debug!("BLOCKING ON DB");
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
    let ctx = ctx.clone();
    smol::future::block_on(async move {
        match db_read(&ctx, "debts").await {
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

pub static MY_CLIENT_ID: CtxField<ClientId> = |_| {
    let rando = rand::random::<u64>();
    rando / 100000 * 100000
};

pub static SETTLEMENTS: CtxField<Settlements> = |ctx| Settlements::new(ctx.init().auto_settle);
