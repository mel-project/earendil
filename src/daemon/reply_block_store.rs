use std::{collections::VecDeque, num::NonZeroUsize};

use earendil_crypt::Fingerprint;
use earendil_packet::ReplyBlock;
use lru::LruCache;

struct ReplyBlockDeque {
    pub deque: VecDeque<ReplyBlock>,
    pub capacity: usize,
}

impl ReplyBlockDeque {
    fn new(capacity: usize) -> Self {
        ReplyBlockDeque {
            deque: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn insert(&mut self, item: ReplyBlock) {
        if self.deque.len() == self.capacity {
            // remove the oldest element
            self.deque.pop_front();
        }
        // add the new element to the end
        self.deque.push_back(item);
    }

    fn pop(&mut self) -> Option<ReplyBlock> {
        self.deque.pop_back()
    }
}

pub struct ReplyBlockStore {
    items: LruCache<Fingerprint, ReplyBlockDeque>,
}

impl ReplyBlockStore {
    pub fn new(size: NonZeroUsize) -> Self {
        let items = LruCache::new(size);
        Self { items }
    }

    pub fn insert(&mut self, fingerprint: Fingerprint, rb: ReplyBlock) {
        match self.items.get_mut(&fingerprint) {
            Some(deque) => {
                deque.insert(rb);
            }
            None => {
                let mut deque = ReplyBlockDeque::new(1000);
                deque.insert(rb);
                self.items.put(fingerprint, deque);
            }
        }
    }

    pub fn insert_batch(&mut self, fingerprint: Fingerprint, items: Vec<ReplyBlock>) {
        for item in items {
            self.insert(fingerprint, item);
        }
    }

    pub fn get(&mut self, fingerprint: &Fingerprint) -> Option<ReplyBlock> {
        match self.items.get_mut(fingerprint) {
            Some(deque) => deque.pop(),
            None => None,
        }
    }
}
