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
    pub fn new() -> Self {
        let items =
            LruCache::new(NonZeroUsize::new(5000).expect("reply block store can't be of size 0"));
        Self { items }
    }

    pub fn insert(&mut self, fingerprint: Fingerprint, rb: ReplyBlock) {
        let deque = self
            .items
            .get_or_insert_mut(fingerprint, || ReplyBlockDeque::new(1000));
        deque.insert(rb);
    }

    pub fn pop(&mut self, fingerprint: &Fingerprint) -> Option<ReplyBlock> {
        match self.items.get_mut(fingerprint) {
            Some(deque) => deque.pop(),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use earendil_crypt::IdentitySecret;
    use earendil_packet::crypt::OnionSecret;
    use earendil_packet::ForwardInstruction;

    fn generate_forward_instructions(n: usize) -> Vec<(ForwardInstruction, OnionSecret)> {
        (0..n)
            .map(|_| {
                let our_sk = OnionSecret::generate();
                let this_pubkey = our_sk.public();

                let next_fingerprint = Fingerprint::from_bytes(&[10; 20]);
                (
                    ForwardInstruction {
                        this_pubkey,
                        next_fingerprint,
                    },
                    our_sk,
                )
            })
            .collect()
    }

    fn create_reply_block() -> ReplyBlock {
        let route_with_onion_secrets = generate_forward_instructions(1);
        let route: Vec<ForwardInstruction> = route_with_onion_secrets
            .iter()
            .map(|(inst, _)| *inst)
            .collect();
        let alice_osk = OnionSecret::generate();
        let alice_opk = alice_osk.public();
        let alice_isk = IdentitySecret::generate();

        let (rb, _) = ReplyBlock::new(&route, &alice_opk, OnionSecret::generate(), alice_isk)
            .expect("Failed to create reply block");
        rb
    }

    #[test]
    fn test_reply_block_deque_insert() {
        let mut rb_deque = ReplyBlockDeque::new(3);
        assert_eq!(rb_deque.deque.len(), 0);

        // Testing insertion when not yet at capacity
        let rb1 = create_reply_block();
        rb_deque.insert(rb1);
        assert_eq!(rb_deque.deque.len(), 1);

        // Testing insertion at capacity
        let rb2 = create_reply_block();
        let rb3 = create_reply_block();
        rb_deque.insert(rb2);
        rb_deque.insert(rb3);
        assert_eq!(rb_deque.deque.len(), 3);

        // Testing insertion when over capacity
        let rb4 = create_reply_block();
        rb_deque.insert(rb4);
        assert_eq!(rb_deque.deque.len(), 3);
    }

    #[test]
    fn test_reply_block_deque_pop() {
        let mut rb_deque = ReplyBlockDeque::new(3);
        let rb = create_reply_block();
        rb_deque.insert(rb.clone());

        // Testing pop when items are present
        assert_eq!(rb_deque.pop(), Some(rb));

        // Testing pop when no items are present
        assert_eq!(rb_deque.pop(), None);
    }

    #[test]
    fn test_reply_block_store_insert() {
        let mut rb_store = ReplyBlockStore::new();
        let fingerprint = Fingerprint::from_bytes(&[10; 20]);
        let rb = create_reply_block();

        // Testing insert in empty store
        rb_store.insert(fingerprint, rb.clone());
        assert_eq!(rb_store.pop(&fingerprint), Some(rb));

        // Testing insert when item already exists
        let rb_new = create_reply_block();
        rb_store.insert(fingerprint, rb_new.clone());
        assert_eq!(rb_store.pop(&fingerprint), Some(rb_new));
    }

    #[test]
    fn test_reply_block_store_pop() {
        let mut rb_store = ReplyBlockStore::new();
        let fingerprint = Fingerprint::from_bytes(&[10; 20]);
        let rb = create_reply_block();

        // Testing get when item exists
        rb_store.insert(fingerprint, rb.clone());
        assert_eq!(rb_store.pop(&fingerprint), Some(rb));

        // Testing get when item does not exist
        assert_eq!(rb_store.pop(&fingerprint), None);
    }
}
