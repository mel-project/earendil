use std::collections::HashMap;

use anyhow::Context;
use parking_lot::RwLock;
use smol::channel::{Receiver, Sender};

pub struct Spider<T, U> {
    inner: RwLock<HashMap<T, (Sender<U>, Receiver<U>)>>,
}

impl<T: Eq + std::hash::Hash + Clone, U> Spider<T, U> {
    pub fn new() -> Self {
        Self {
            inner: Default::default(),
        }
    }

    pub fn subscribe(&self, val: T) -> Receiver<U> {
        self.cleanup();
        let mut inner = self.inner.write();
        inner
            .entry(val)
            .or_insert_with(|| smol::channel::bounded(1000))
            .1
            .clone()
    }

    pub fn send(&self, dest: &T, val: U) -> anyhow::Result<()> {
        let inner = self.inner.read();
        let chan = inner.get(dest).context("no such destination")?;
        let _ = chan.0.try_send(val);
        Ok(())
    }

    pub fn contains(&self, val: &T) -> bool {
        self.inner.read().contains_key(val)
    }

    pub fn keys(&self) -> Vec<T> {
        self.inner.read().keys().cloned().collect()
    }

    fn cleanup(&self) {
        self.inner.write().retain(|_, v| v.0.receiver_count() > 1)
    }
}
