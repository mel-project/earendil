use std::{path::PathBuf, str::FromStr};

use anyhow::Context;
use chrono::Utc;
use sqlx::{sqlite::SqliteConnectOptions, SqlitePool};

use super::types::NeighborId;

/// Persistent storage for links, containing debts and chats.
pub struct DebtStore {
    pool: SqlitePool,
}

impl DebtStore {
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
            "CREATE TABLE IF NOT EXISTS debts (
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
}
