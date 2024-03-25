use dashmap::DashMap;
use earendil_crypt::{ClientId, RelayFingerprint};
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, time::SystemTime};

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

    pub async fn wait_unsent(
        &self,
        _neighbor: either::Either<ClientId, RelayFingerprint>,
    ) -> Vec<ChatEntry> {
        // this must return all the outgoing messages to the given neighbor that *have not yet been returned by this function*.
        // additionall bookkeeping is certainly needed for this.
        todo!()
    }
}

impl ChatEntry {
    pub fn new_outgoing(text: String) -> Self {
        Self {
            is_incoming: true,
            text,
            time: SystemTime::now(),
        }
    }

    pub fn new_incoming(text: String) -> Self {
        Self {
            is_incoming: false,
            text,
            time: SystemTime::now(),
        }
    }
}
