use std::{path::PathBuf, str::FromStr};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqliteConnectOptions, SqlitePool};

use super::types::NeighborId;

pub struct LinkStore {
    pool: SqlitePool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatEntry {
    pub text: String,
    /// unix timestamp
    pub timestamp: u64,
    pub is_outgoing: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DebtEntry {
    /// micromels
    pub delta: i64,
    /// unix timestamp
    pub timestamp: u64,
    pub proof: Option<String>,
}

impl LinkStore {
    pub async fn new(path: PathBuf) -> anyhow::Result<Self> {
        tracing::debug!("INITIALIZING DATABASE");
        let options =
            SqliteConnectOptions::from_str(path.to_str().context("db-path is not valid unicode")?)
                .unwrap()
                .create_if_missing(true);
        let pool = SqlitePool::connect_with(options).await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS chats (
                    id INTEGER PRIMARY KEY,
                    neighbor TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    text TEXT NOT NULL,
                    is_outgoing BOOL NOT NULL);

                CREATE TABLE IF NOT EXISTS debts (
                    id INTEGER PRIMARY KEY,
                    neighbor TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    delta INTEGER NOT NULL,
                    proof TEXT NULL);
            
                CREATE TABLE IF NOT EXISTS misc (
                    key TEXT PRIMARY KEY,
                    value BLOB NOT NULL);",
        )
        .execute(&pool)
        .await?;
        Ok(Self { pool })
    }

    pub async fn insert_chat_entry(
        &self,
        neighbor: NeighborId,
        chat_entry: ChatEntry,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO chats (neighbor, timestamp, text, is_outgoing) VALUES ($1, $2, $3, $4)",
        )
        .bind(serde_json::to_string(&neighbor)?)
        .bind(chat_entry.timestamp as i64)
        .bind(chat_entry.text)
        .bind(chat_entry.is_outgoing)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_chat_history(&self, neighbor: NeighborId) -> anyhow::Result<Vec<ChatEntry>> {
        let res: Vec<(i64, String, bool)> =
            sqlx::query_as("SELECT  timestamp, text, is_outgoing FROM chats WHERE neighbor = $1")
                .bind(serde_json::to_string(&neighbor)?)
                .fetch_all(&self.pool)
                .await?;
        Ok(res
            .into_iter()
            .map(|(timestamp, text, is_outgoing)| ChatEntry {
                text,
                timestamp: timestamp as u64,
                is_outgoing,
            })
            .collect())
    }

    pub async fn insert_debt_entry(
        &self,
        neighbor: NeighborId,
        debt_entry: DebtEntry,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO debts (neighbor, timestamp, delta, proof) VALUES ($1, $2, $3, $4)",
        )
        .bind(serde_json::to_string(&neighbor)?)
        .bind(debt_entry.timestamp as i64)
        .bind(debt_entry.delta)
        .bind(debt_entry.proof)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_debt(&self, neighbor: NeighborId) -> anyhow::Result<i64> {
        let res: Option<(i64,)> =
            sqlx::query_as("SELECT SUM(delta) FROM debts WHERE neighbor = $1")
                .bind(serde_json::to_string(&neighbor)?)
                .fetch_optional(&self.pool)
                .await?;
        Ok(res.map(|(sum,)| sum).unwrap_or(0))
    }

    pub async fn insert_misc(&self, key: String, value: Vec<u8>) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO misc (key, value) VALUES ($1, $2) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_misc(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let result: Option<(Vec<u8>,)> = sqlx::query_as("SELECT value FROM misc WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(result.map(|(val,)| val))
    }
}
