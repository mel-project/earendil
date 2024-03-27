use async_event::Event;
use dashmap::DashMap;
use earendil_crypt::{ClientId, RelayFingerprint};
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, sync::Arc, time::SystemTime};

use crate::context::CtxField;

pub static CHATS: CtxField<Chats> = |_| {
    tracing::debug!("initializing chats");
    Chats::new(usize::MAX)
};

#[derive(Serialize, Deserialize)]
pub struct Chats {
    history: DashMap<either::Either<ClientId, RelayFingerprint>, VecDeque<ChatEntry>>,
    max_chat_len: usize,
    #[serde(skip)]
    unsent: Arc<Event>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ChatEntry {
    pub is_incoming: bool,
    pub text: String,
    pub time: SystemTime,
    pub is_seen: bool,
}

impl Chats {
    pub fn new(max_chat_len: usize) -> Self {
        Self {
            history: DashMap::new(),
            max_chat_len,
            unsent: Arc::new(Event::new()),
        }
    }

    pub fn record(&self, neighbor: either::Either<ClientId, RelayFingerprint>, entry: ChatEntry) {
        let mut chat = self.history.entry(neighbor).or_default();
        if chat.len() >= self.max_chat_len {
            chat.pop_front();
        }

        chat.push_back(entry);
        self.unsent.notify_all();
    }

    pub async fn wait_unsent(
        &self,
        neighbor: either::Either<ClientId, RelayFingerprint>,
    ) -> Vec<ChatEntry> {
        self.unsent
            .wait_until(move || {
                let mut unsent = vec![];
                if let Some(mut chat) = self.history.get_mut(&neighbor) {
                    for entry in chat.iter_mut() {
                        if !entry.is_incoming && !entry.is_seen {
                            entry.is_seen = true;
                            unsent.push(entry.clone());
                        }
                    }
                }
                if unsent.is_empty() {
                    None
                } else {
                    Some(unsent)
                }
            })
            .await
    }

    pub fn dump_convo(
        &self,
        neighbor: either::Either<ClientId, RelayFingerprint>,
    ) -> Vec<ChatEntry> {
        self.history.entry(neighbor).or_default().clone().into()
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
