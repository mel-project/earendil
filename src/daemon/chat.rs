use dashmap::DashMap;
use earendil_crypt::{ClientId, RelayFingerprint};
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, time::SystemTime};

use crate::context::CtxField;

pub static CHATS: CtxField<Chats> = |_| {
    tracing::debug!("initializing chats");
    Chats::new(usize::MAX)
};

#[derive(Serialize, Deserialize)]
pub struct Chats {
    history: DashMap<either::Either<ClientId, RelayFingerprint>, VecDeque<ChatEntry>>,
    max_chat_len: usize,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ChatEntry {
    is_incoming: bool,
    text: String,
    time: SystemTime,
    is_seen: bool,
}

impl Chats {
    pub fn new(max_chat_len: usize) -> Self {
        Self {
            history: DashMap::new(),
            max_chat_len,
        }
    }

    pub fn record(&self, neighbor: either::Either<ClientId, RelayFingerprint>, entry: ChatEntry) {
        let mut chat = self.history.entry(neighbor).or_default();
        if chat.len() >= self.max_chat_len {
            chat.pop_front();
        }

        chat.push_back(entry);
    }

    pub fn wait_unsent(
        &self,
        neighbor: either::Either<ClientId, RelayFingerprint>,
    ) -> Vec<ChatEntry> {
        let mut unsent = vec![];
        if let Some(mut chat) = self.history.get_mut(&neighbor) {
            for entry in chat.iter_mut() {
                if !entry.is_incoming && !entry.is_seen {
                    entry.is_seen = true;
                    unsent.push(entry.clone());
                }
            }
        }

        unsent
    }

    pub fn dump_convo(
        &self,
        neighbor: either::Either<ClientId, RelayFingerprint>,
    ) -> Vec<ChatEntry> {
        match self.history.get(&neighbor) {
            Some(chat_history) => chat_history.clone().into(),
            None => vec![],
        }
    }
}

impl ChatEntry {
    pub fn new_outgoing(text: String) -> Self {
        Self {
            is_incoming: true,
            text,
            time: SystemTime::now(),
            is_seen: false,
        }
    }

    pub fn new_incoming(text: String) -> Self {
        Self {
            is_incoming: false,
            text,
            time: SystemTime::now(),
            is_seen: false,
        }
    }
}
