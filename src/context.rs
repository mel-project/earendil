use std::time::Duration;

use blake3::Hash;
use bytes::Bytes;
use dashmap::{DashMap, DashSet};
use earendil_crypt::{AnonRemote, ClientId, RelayFingerprint, RelayIdentitySecret, RemoteId};
use earendil_packet::{crypt::OnionSecret, Dock, Message, RawBody, RawPacket, ReplyDegarbler};
use earendil_topology::RelayGraph;

use moka::sync::{Cache, CacheBuilder};
use parking_lot::RwLock;
use smol::channel::Sender;

use crate::{
    config::ConfigFile,
    db::db_read,
    debts::Debts,
    settlement::Settlements,
    socket::{AnonEndpoint, RelayEndpoint},
};

pub type DaemonContext = anyctx::AnyCtx<ConfigFile>;
pub type CtxField<T> = fn(&DaemonContext) -> T;

pub static GLOBAL_IDENTITY: CtxField<Option<RelayIdentitySecret>> = |ctx| {
    tracing::debug!("INITIALIZING GLOBAL IDENTITY");
    if ctx.init().in_routes.is_empty() {
        None
    } else {
        Some(
            ctx.init()
                .identity
                .as_ref()
                .map(|id| {
                    id.actualize_relay()
                        .expect("failed to initialize global identity")
                })
                .unwrap_or_else(|| {
                    let ctx = ctx.clone();
                    smol::future::block_on(async move {
                        match db_read(&ctx, "global_identity").await {
                            Ok(Some(id)) => {
                                if let Ok(id_bytes) = &id.try_into() {
                                    RelayIdentitySecret::from_bytes(id_bytes)
                                } else {
                                    RelayIdentitySecret::generate()
                                }
                            }
                            _ => RelayIdentitySecret::generate(),
                            Err(_) => todo!(),
                        }
                    })
                }),
        )
    }
};

pub static GLOBAL_ONION_SK: CtxField<OnionSecret> = |_| OnionSecret::generate();
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

pub static RELAY_NEIGHS: CtxField<Cache<RelayFingerprint, Sender<(RawPacket, RelayFingerprint)>>> =
    |_| {
        CacheBuilder::default()
            .time_to_live(Duration::from_secs(120))
            .build()
    }; // TODO a better solution for deletion

pub static CLIENT_TABLE: CtxField<Cache<ClientId, Sender<(RawBody, u64)>>> = |_| {
    CacheBuilder::default()
        .time_to_live(Duration::from_secs(120))
        .build()
};

pub static DEGARBLERS: CtxField<DashMap<u64, ReplyDegarbler>> = |_| Default::default();

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
