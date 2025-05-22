use std::{collections::HashMap, path::PathBuf, str::FromStr};

use anyhow::Context;
use chrono::Utc;
use earendil_topology::NodeAddr;
use serde::{Deserialize, Serialize};
use sqlx::{SqlitePool, sqlite::SqliteConnectOptions};

/// Persistent storage for chats and misc data.
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
        neighbor: NodeAddr,
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

    pub async fn get_chat_history(&self, neighbor: NodeAddr) -> anyhow::Result<Vec<ChatEntry>> {
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

    pub async fn get_chat_summary(&self) -> anyhow::Result<Vec<(NodeAddr, ChatEntry, u32)>> {
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
}
