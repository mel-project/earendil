use super::context::DaemonContext;
use crate::daemon::context::CtxField;
use sqlx::{sqlite::SqliteConnectOptions, Pool, SqlitePool};
use std::future::Future;
use std::str::FromStr;

static DATABASE: CtxField<Box<dyn Future<Output = Result<SqlitePool, sqlx::Error>>>> = |ctx| {
    let options = match &ctx.init().db_path {
        Some(path) => SqliteConnectOptions::from_str(path.to_str().unwrap())
            .unwrap()
            .create_if_missing(true),
        None => SqliteConnectOptions::from_str(":memory:").unwrap(),
    };
    Box::new(Pool::connect_with(options))
};

async fn db_write<T>(ctx: DaemonContext, key: &str, value: T) -> anyhow::Result<()> {
    Ok(())
}

fn db_read(ctx: DaemonContext, key: &str) {}
