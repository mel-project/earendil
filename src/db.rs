use sqlx::sqlite::SqliteConnectOptions;
use sqlx::Pool;
use sqlx::Row;
use sqlx::SqlitePool;
use std::str::FromStr;

use crate::context::{CtxField, DaemonContext};

static DATABASE: CtxField<Option<SqlitePool>> = |ctx| {
    tracing::debug!("INITIALIZING DATABASE");
    if let Some(db_path) = &ctx.init().state_cache {
        let options = SqliteConnectOptions::from_str(db_path.to_str().unwrap())
            .unwrap()
            .create_if_missing(true);

        smol::future::block_on(async move {
            let pool = Pool::connect_with(options).await.unwrap();
            sqlx::query(
                "CREATE TABLE IF NOT EXISTS misc (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );",
            )
            .execute(&pool)
            .await
            .unwrap();

            Some(pool)
        })
    } else {
        None
    }
};

pub async fn db_write(ctx: &DaemonContext, key: &str, value: Vec<u8>) -> Result<(), sqlx::Error> {
    if let Some(pool) = ctx.get(DATABASE) {
        sqlx::query("INSERT INTO misc (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
        .bind(key)
        .bind(value)
        .execute(pool)
        .await?;
    }
    Ok(())
}

pub async fn db_read(ctx: &DaemonContext, key: &str) -> Result<Option<Vec<u8>>, sqlx::Error> {
    if let Some(pool) = ctx.get(DATABASE) {
        let result = sqlx::query("SELECT value FROM misc WHERE key = ?")
            .bind(key)
            .fetch_optional(pool)
            .await?
            .map(|row| row.get("value"));
        Ok(result)
    } else {
        Ok(None)
    }
}
