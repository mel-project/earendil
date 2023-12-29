use std::{
    collections::{HashMap, VecDeque},
    time::SystemTime,
};

use dashmap::DashMap;
use earendil_crypt::Fingerprint;
use serde::{Deserialize, Serialize};

use super::{
    context::{CtxField, DaemonContext},
    db::db_read,
};

static CHATS: CtxField<Chats> = |ctx| {
    let max_chat_len = usize::MAX;
    let ctx = ctx.clone();

    smolscale::block_on(async move {
        match db_read(&ctx, "chats").await {
            Ok(Some(chats)) => {
                log::warn!("retrieving persisted chats");
                match Chats::from_bytes(chats) {
                    Ok(chats) => chats,
                    Err(e) => {
                        log::warn!("{e}");
                        Chats::new(max_chat_len)
                    }
                }
            }
            _ => {
                log::warn!("initializing debts");
                Chats::new(max_chat_len)
            }
        }
    })
};

pub fn incoming_chat(ctx: DaemonContext, neighbor: Fingerprint, entry: ChatEntry) {
    let chats = ctx.get(CHATS);
    chats.insert(neighbor, entry);
}

#[derive(Clone)]
struct Chats {
    history: DashMap<Fingerprint, VecDeque<ChatEntry>>,
    max_chat_len: usize,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ChatEntry {
    is_mine: bool,
    text: String,
    time: SystemTime,
}

impl Chats {
    fn new(max_chat_len: usize) -> Self {
        let history: DashMap<Fingerprint, VecDeque<ChatEntry>> = DashMap::new();
        Self {
            history,
            max_chat_len,
        }
    }

    fn insert(&self, neighbor: Fingerprint, entry: ChatEntry) {
        let mut chat = self.history.entry(neighbor).or_default();
        if chat.len() >= self.max_chat_len {
            chat.pop_front();
        }
        chat.push_back(entry);
    }

    fn into_bytes(self) -> anyhow::Result<Vec<u8>> {
        let history: HashMap<Fingerprint, VecDeque<ChatEntry>> = self.history.into_iter().collect();
        let max_chat_len = self.max_chat_len;
        Ok(stdcode::serialize(&(history, max_chat_len))?)
    }

    fn from_bytes(bytes: Vec<u8>) -> anyhow::Result<Self> {
        let (history, max_chat_len): (HashMap<Fingerprint, VecDeque<ChatEntry>>, usize) =
            stdcode::deserialize(&bytes)?;
        Ok(Self {
            history: history.into_iter().collect(),
            max_chat_len,
        })
    }
}

impl ChatEntry {
    pub fn new(text: String) -> Self {
        Self {
            is_mine: true,
            text,
            time: SystemTime::now(),
        }
    }
}
