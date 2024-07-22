use std::{collections::HashMap, path::PathBuf, str::FromStr};

use anyhow::Context;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqliteConnectOptions, SqlitePool};

use super::types::NeighborId;

/// Persistent storage for links, containing debts and chats.
pub struct LinkStore {
    pool: SqlitePool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ChatEntry {
    pub text: String,
    /// unix timestamp
    pub timestamp: i64,
    pub is_outgoing: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DebtEntry {
    /// micromels
    pub delta: f64,
    /// unix timestamp
    pub timestamp: i64,
    pub proof: Option<String>,
}

impl LinkStore {
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
                        id INTEGER PRIMARY KEY,
                        neighbor TEXT NOT NULL,
                        timestamp INTEGER NOT NULL,
                        delta REAL NOT NULL,
                        proof TEXT NULL);

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

    pub async fn insert_chat_entry(
        &self,
        neighbor: NeighborId,
        chat_entry: ChatEntry,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO chats (neighbor, timestamp, text, is_outgoing) VALUES ($1, $2, $3, $4)",
        )
        .bind(serde_json::to_string(&neighbor)?)
        .bind(chat_entry.timestamp)
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
                timestamp,
                is_outgoing,
            })
            .collect())
    }

    pub async fn get_chat_summary(&self) -> anyhow::Result<Vec<(NeighborId, ChatEntry, u32)>> {
        let res: Vec<(String, i64, String, bool, i32)> = sqlx::query_as(
            r#"
            SELECT
                c.neighbor,
                c.timestamp,
                c.text,
                c.is_outgoing,
                count_subquery.count
            FROM
                chats c
            JOIN
                (SELECT neighbor, MAX(id) as max_id, COUNT(*) as count
                FROM chats
                GROUP BY neighbor) count_subquery
            ON
                c.neighbor = count_subquery.neighbor AND c.id = count_subquery.max_id;
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(res
            .into_iter()
            .map(|(neighbor, timestamp, text, is_outgoing, count)| {
                (
                    serde_json::from_str(&neighbor).unwrap(),
                    ChatEntry {
                        text: text.clone(),
                        timestamp,
                        is_outgoing,
                    },
                    count as _,
                )
            })
            .collect())
    }

    pub async fn delta_debt(
        &self,
        neighbor: NeighborId,
        delta: f64,
        proof: Option<String>,
    ) -> anyhow::Result<()> {
        self.insert_debt_entry(
            neighbor,
            DebtEntry {
                delta,
                timestamp: chrono::Utc::now().timestamp(),
                proof,
            },
        )
        .await
    }

    async fn insert_debt_entry(
        &self,
        neighbor: NeighborId,
        debt_entry: DebtEntry,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO debts (neighbor, timestamp, delta, proof) VALUES ($1, $2, $3, $4)",
        )
        .bind(serde_json::to_string(&neighbor)?)
        .bind(debt_entry.timestamp)
        .bind(debt_entry.delta)
        .bind(debt_entry.proof)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_debt(&self, neighbor: NeighborId) -> anyhow::Result<f64> {
        let res: Option<(f64,)> =
            sqlx::query_as("SELECT SUM(delta) FROM debts WHERE neighbor = $1")
                .bind(serde_json::to_string(&neighbor)?)
                .fetch_optional(&self.pool)
                .await?;
        Ok(res.map(|(sum,)| sum).unwrap_or(0.0))
    }

    pub async fn get_debt_summary(&self) -> anyhow::Result<HashMap<String, f64>> {
        let res: Vec<(String, f64)> = sqlx::query_as(
            "SELECT neighbor, SUM(delta) as total_delta FROM debts GROUP BY neighbor",
        )
        .fetch_all(&self.pool)
        .await?;

        let summary = res.into_iter().collect::<HashMap<String, f64>>();
        Ok(summary)
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

    pub async fn get_or_insert_misc(&self, key: &str, value: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        if let Some(val) = self.get_misc(key).await? {
            Ok(val)
        } else {
            self.insert_misc(key.to_string(), value.clone()).await?;
            Ok(value)
        }
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

    /// returns Some(timestamp) = when the ott was created if was valid, None otherwise
    pub async fn check_and_consume_ott(&self, ott: &str) -> anyhow::Result<Option<i64>> {
        let res: Option<(i64,)> = sqlx::query_as("SELECT timestamp FROM otts WHERE ott=$1")
            .bind(ott)
            .fetch_optional(&self.pool)
            .await?;
        if let Some((timestamp,)) = res {
            sqlx::query("DELETE FROM otts where ott=$1")
                .bind(ott)
                .execute(&self.pool)
                .await?;
            Ok(Some(timestamp))
        } else {
            Ok(None)
        }
    }
}
