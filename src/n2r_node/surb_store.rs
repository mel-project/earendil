use std::{collections::VecDeque, num::NonZeroUsize};

use earendil_crypt::AnonEndpoint;
use earendil_packet::Surb;
use lru::LruCache;

pub struct SurbStore {
    items: LruCache<AnonEndpoint, ReplyBlockDeque>,
}

impl Default for SurbStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SurbStore {
    pub fn new() -> Self {
        let items =
            LruCache::new(NonZeroUsize::new(5000).expect("reply block store can't be of size 0"));
        Self { items }
    }

    pub fn insert(&mut self, anon_dest: AnonEndpoint, rb: Surb) {
        let deque = self
            .items
            .get_or_insert_mut(anon_dest, || ReplyBlockDeque::new(1000));
        deque.insert(rb);
    }

    pub fn pop_and_count(&mut self, anon_dest: AnonEndpoint) -> Option<(Surb, usize)> {
        match self.items.get_mut(&anon_dest) {
            Some(deque) => Some((deque.pop()?, deque.deque.len())),
            None => None,
        }
    }
}

struct ReplyBlockDeque {
    pub deque: VecDeque<Surb>,
    pub capacity: usize,
}

impl ReplyBlockDeque {
    fn new(capacity: usize) -> Self {
        ReplyBlockDeque {
            deque: VecDeque::new(),
            capacity,
        }
    }

    fn insert(&mut self, item: Surb) {
        if self.deque.len() == self.capacity {
            // remove the oldest element
            self.deque.pop_front();
        }
        // add the new element to the end
        self.deque.push_back(item);
    }

    fn pop(&mut self) -> Option<Surb> {
        self.deque.pop_back()
    }
}
