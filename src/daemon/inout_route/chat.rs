use crate::daemon::inout_route::LinkClient;
use crate::daemon::{context::DaemonContext, db::db_read};
use dashmap::DashMap;
use earendil_crypt::Fingerprint;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::SystemTime,
};

use crate::daemon::context::{CtxField, NEIGH_TABLE_NEW};

static CHATS: CtxField<Chats> = |ctx| {
    let max_chat_len = usize::MAX;
    let ctx = ctx.clone();

    smolscale::block_on(async move {
        match db_read(&ctx, "chats").await {
            Ok(Some(chats)) => {
                tracing::debug!("retrieving persisted chats");
                match Chats::from_bytes(chats) {
                    Ok(chats) => chats,
                    Err(e) => {
                        tracing::warn!("error retrieving persisted chats: {e}");
                        Chats::new(max_chat_len)
                    }
                }
            }
            _ => {
                tracing::debug!("no persisted chats");
                Chats::new(max_chat_len)
            }
        }
    })
};

pub fn incoming_chat(ctx: &DaemonContext, neighbor: Fingerprint, msg: String) {
    let chats = ctx.get(CHATS);
    let entry = ChatEntry::new_incoming(msg);
    chats.insert(neighbor, entry);
}

pub fn list_neighbors(ctx: &DaemonContext) -> Vec<Fingerprint> {
    ctx.get(NEIGH_TABLE_NEW)
        .iter()
        .map(|neigh| *neigh.0)
        .collect()
}

pub fn list_chats(ctx: &DaemonContext) -> String {
    let mut info = "+----------------------------------+-------------------+-----------------------------------+\n".to_owned();
    info +=    "| Neighbor                         | # of Messages     | Last chat                         |\n";
    info +=    "+----------------------------------+-------------------+-----------------------------------+\n";

    for entry in ctx.get(CHATS).history.iter() {
        let (neigh, chat) = entry.pair();
        let num_messages = chat.len();
        if let Some(ChatEntry {
            is_mine: _,
            text,
            time,
        }) = chat.back()
        {
            info += &format!(
                "| {:<32} | {:<17} | {} {}\n",
                neigh,
                num_messages,
                text,
                create_timestamp(*time)
            );
            info += "+----------------------------------+-------------------+-----------------------------------+\n";
        }
    }

    info
}

pub fn add_client(ctx: &DaemonContext, neighbor: Fingerprint, client: Arc<LinkClient>) {
    ctx.get(CHATS).clients.insert(neighbor, client);
}

pub fn remove_client(ctx: &DaemonContext, neighbor: &Fingerprint) {
    ctx.get(CHATS).clients.remove(neighbor);
}

pub fn get_chat(ctx: &DaemonContext, neigh: Fingerprint) -> Vec<(bool, String, SystemTime)> {
    ctx.get(CHATS)
        .get(neigh)
        .iter()
        .map(|entry| (entry.is_mine, entry.text.clone(), entry.time))
        .collect()
}

#[tracing::instrument(skip(ctx))]
pub async fn send_chat_msg(ctx: &DaemonContext, dest: Fingerprint, msg: String) {
    let chats = ctx.get(CHATS);

    if let Some(client) = chats.clients.get(&dest) {
        match client.push_chat(msg.clone()).await {
            Ok(_) => chats.insert(dest, ChatEntry::new_outgoing(msg)),
            Err(e) => tracing::warn!("error pushing chat: {e}"),
        }
    }
}

pub fn serialize_chats(ctx: &DaemonContext) -> anyhow::Result<Vec<u8>> {
    ctx.get(CHATS).clone().into_bytes()
}

pub fn create_timestamp(now: SystemTime) -> String {
    let datetime: chrono::DateTime<chrono::Local> = now.into();

    format!("[{}]", datetime.format("%Y-%m-%d %H:%M:%S"))
}

#[derive(Clone)]
struct Chats {
    history: DashMap<Fingerprint, VecDeque<ChatEntry>>,
    clients: DashMap<Fingerprint, Arc<LinkClient>>,
    max_chat_len: usize,
}

#[derive(Clone, Serialize, Deserialize)]
struct ChatEntry {
    is_mine: bool,
    text: String,
    time: SystemTime,
}

impl Chats {
    fn new(max_chat_len: usize) -> Self {
        let history: DashMap<Fingerprint, VecDeque<ChatEntry>> = DashMap::new();
        let clients: DashMap<Fingerprint, Arc<LinkClient>> = DashMap::new();
        Self {
            history,
            clients,
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

    fn get(&self, neighbor: Fingerprint) -> Vec<ChatEntry> {
        self.history
            .get(&neighbor)
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    fn get_latest(&self, neighbor: Fingerprint) -> Option<ChatEntry> {
        if let Some(history) = self.history.get(&neighbor) {
            history.back().cloned()
        } else {
            None
        }
    }

    fn into_bytes(self) -> anyhow::Result<Vec<u8>> {
        let history: HashMap<Fingerprint, VecDeque<ChatEntry>> = self.history.into_iter().collect();
        Ok(stdcode::serialize(&(history, self.max_chat_len))?)
    }

    fn from_bytes(bytes: Vec<u8>) -> anyhow::Result<Self> {
        let (history, max_chat_len): (HashMap<Fingerprint, VecDeque<ChatEntry>>, usize) =
            stdcode::deserialize(&bytes)?;
        Ok(Self {
            history: history.into_iter().collect(),
            clients: DashMap::new(),
            max_chat_len,
        })
    }
}

impl ChatEntry {
    fn new_outgoing(text: String) -> Self {
        Self {
            is_mine: true,
            text,
            time: SystemTime::now(),
        }
    }

    fn new_incoming(text: String) -> Self {
        Self {
            is_mine: false,
            text,
            time: SystemTime::now(),
        }
    }
}
