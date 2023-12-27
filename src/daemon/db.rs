use sqlx::sqlite::SqliteConnectOptions;
use sqlx::Pool;
use sqlx::Row;
use sqlx::SqlitePool;
use std::str::FromStr;

use super::context::{CtxField, DaemonContext};

static DATABASE: CtxField<SqlitePool> = |ctx| {
    let options = SqliteConnectOptions::from_str(ctx.init().db_path.to_str().unwrap())
        .unwrap()
        .create_if_missing(true);

    smolscale::block_on(async move {
        let pool = Pool::connect_with(options).await.unwrap();
        let _ = sqlx::query(
            "CREATE TABLE IF NOT EXISTS misc (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL
        );",
        )
        .execute(&pool)
        .await;
        pool
    })
};

pub async fn db_write(ctx: &DaemonContext, key: &str, value: Vec<u8>) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO misc (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
        .bind(key)
        .bind(value)
        .execute(ctx.get(DATABASE))
        .await?;
    Ok(())
}

pub async fn db_read(ctx: &DaemonContext, key: &str) -> Result<Option<Vec<u8>>, sqlx::Error> {
    let pool = ctx.get(DATABASE);
    let result = sqlx::query("SELECT value FROM misc WHERE key = ?")
        .bind(key)
        .fetch_optional(pool)
        .await?
        .map(|row| row.get("value"));
    Ok(result)
}
