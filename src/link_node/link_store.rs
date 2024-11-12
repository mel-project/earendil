use std::{
    collections::HashMap,
    path::PathBuf,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqliteConnectOptions, SqlitePool};

use super::types::NeighborId;

/// Persistent storage for links, containing debts and chats.
pub struct LinkStore {
    pool: SqlitePool,
}

impl LinkStore {
    /// Creates a new
    pub async fn new(path: PathBuf) -> anyhow::Result<Self> {
        tracing::debug!("INITIALIZING DATABASE");
        let options =
            SqliteConnectOptions::from_str(path.to_str().context("db-path is not valid unicode")?)?
                .create_if_missing(true)
                .foreign_keys(true)
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
                .synchronous(sqlx::sqlite::SqliteSynchronous::Normal);
        let pool = SqlitePool::connect_with(options).await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS chats (
                    id INTEGER PRIMARY KEY,
                    neighbor TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    text TEXT NOT NULL,
                    is_outgoing BOOL NOT NULL);

                CREATE TABLE IF NOT EXISTS debts (
                        neighbor TEXT NOT NULL NOT NULL,
                        debt REAL NOT NULL,
                        timestamp INTEGER NOT NULL);

                CREATE TABLE IF NOT EXISTS otts (
                    ott TEXT NOT NULL,
                    timestamp INTEGER NOT NULL);

                CREATE TABLE IF NOT EXISTS misc (
                    key TEXT PRIMARY KEY,
                    value BLOB NOT NULL);",
        )
        .execute(&pool)
        .await?;
        Ok(Self { pool })
    }

    pub async fn delta_debt(&self, neighbor: NeighborId, delta: f64) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO debts (neighbor, debt, timestamp) 
             VALUES ($1, $2, $3)
             ON CONFLICT (neighbor) DO UPDATE SET
             debt = debts.debt + $2,
             timestamp = $3",
        )
        .bind(neighbor.to_string())
        .bind(delta)
        .bind(Utc::now().timestamp())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_ott(&self) -> anyhow::Result<String> {
        let ott = rand::random::<u128>().to_string();
        sqlx::query("INSERT INTO otts (ott, timestamp) VALUES ($1, $2)")
            .bind(ott.clone())
            .bind(Utc::now().timestamp())
            .execute(&self.pool)
            .await?;
        Ok(ott)
    }

    pub async fn consume_ott(&self, ott: &str) -> anyhow::Result<Option<SystemTime>> {
        let mut transaction = self.pool.begin().await?;

        let res: Option<(i64,)> = sqlx::query_as("SELECT timestamp FROM otts WHERE ott = $1")
            .bind(ott)
            .fetch_optional(&mut *transaction)
            .await?;

        if let Some((timestamp,)) = res {
            sqlx::query("DELETE FROM otts WHERE ott = $1")
                .bind(ott)
                .execute(&mut *transaction)
                .await?;

            transaction.commit().await?;

            let system_time = UNIX_EPOCH + Duration::from_secs(timestamp as u64);
            Ok(Some(system_time))
        } else {
            transaction.rollback().await?;
            Ok(None)
        }
    }
}
