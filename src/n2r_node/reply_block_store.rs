use std::{collections::VecDeque, num::NonZeroUsize};

use earendil_crypt::AnonEndpoint;
use earendil_packet::ReplyBlock;
use lru::LruCache;

pub struct ReplyBlockStore {
    items: LruCache<AnonEndpoint, ReplyBlockDeque>,
}

impl Default for ReplyBlockStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplyBlockStore {
    pub fn new() -> Self {
        let items =
            LruCache::new(NonZeroUsize::new(5000).expect("reply block store can't be of size 0"));
        Self { items }
    }

    pub fn insert(&mut self, anon_dest: AnonEndpoint, rb: ReplyBlock) {
        let deque = self
            .items
            .get_or_insert_mut(anon_dest, || ReplyBlockDeque::new(1000));
        deque.insert(rb);
    }

    pub fn pop(&mut self, anon_dest: &AnonEndpoint) -> Option<ReplyBlock> {
        match self.items.get_mut(anon_dest) {
            Some(deque) => deque.pop(),
            None => None,
        }
    }
}

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
