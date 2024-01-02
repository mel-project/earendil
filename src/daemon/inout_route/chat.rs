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

use crate::daemon::context::CtxField;

static CHATS: CtxField<Chats> = |ctx| {
    let max_chat_len = usize::MAX;
    let ctx = ctx.clone();

    smolscale::block_on(async move {
        match db_read(&ctx, "chats").await {
            Ok(Some(chats)) => {
                log::debug!("retrieving persisted chats");
                match Chats::from_bytes(chats) {
                    Ok(chats) => chats,
                    Err(e) => {
                        log::warn!("{e}");
                        Chats::new(max_chat_len)
                    }
                }
            }
            _ => {
                log::debug!("initializing debts");
                Chats::new(max_chat_len)
            }
        }
    })
};

pub fn incoming_chat(ctx: &DaemonContext, neighbor: Fingerprint, msg: String) {
    println!("GOT NEW MSG: {}, inserting into chat history", msg.clone());

    let chats = ctx.get(CHATS);
    let entry = ChatEntry::new(msg);

    chats.insert(neighbor, entry);
}

pub fn list_chats(ctx: &DaemonContext) -> String {
    let mut info = String::new();

    for entry in ctx.get(CHATS).history.iter() {
        let (neigh, chat) = entry.pair();
        let num_messages = chat.len();
        let last_chat = chat
            .back()
            .unwrap()
            .time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        info += &format!(
            "Neighbor: {} - Messages: {} - Last chat time (unix timestamp): {}",
            neigh, num_messages, last_chat
        );
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

pub async fn send_chat_msg(ctx: &DaemonContext, dest: Fingerprint, msg: String) {
    let client = ctx.get(CHATS).clients.get(&dest);
    if let Some(client) = client {
        println!("send_chat_msg - pushing chat {}", msg.clone());
        let _ = client.push_chat(msg).await;
    } else {
        log::error!("no client for send msg: {}", dest);
    }
}

pub fn serialize_chats(ctx: &DaemonContext) -> anyhow::Result<Vec<u8>> {
    ctx.get(CHATS).clone().into_bytes()
}

pub fn get_latest_chat(
    ctx: &DaemonContext,
    neighbor: Fingerprint,
) -> Option<(bool, String, SystemTime)> {
    if let Some(entry) = ctx.get(CHATS).get_latest(neighbor) {
        Some((entry.is_mine, entry.text, entry.time))
    } else {
        None
    }
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
        println!("chat insert...");
        if chat.len() >= self.max_chat_len {
            chat.pop_front();
        }

        println!("push back in chat history!");
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
        println!("history is some: {}", self.history.get(&neighbor).is_some());
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
    fn new(text: String) -> Self {
        Self {
            is_mine: true,
            text,
            time: SystemTime::now(),
        }
    }
}
