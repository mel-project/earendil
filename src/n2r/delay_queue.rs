use async_event::Event;
use core::hash::Hash;
use earendil_crypt::RelayFingerprint;
use earendil_packet::RawPacket;
use parking_lot::Mutex;
use priority_queue::priority_queue::PriorityQueue;
use smol::future::FutureExt;
use std::{cmp::Reverse, time::Instant};

use crate::context::CtxField;

pub static DELAY_QUEUE: CtxField<DelayQueue<(RawPacket, RelayFingerprint)>> = |_| DelayQueue::new();

pub struct DelayQueue<T: Hash + Eq> {
    priority_queue: Mutex<PriorityQueue<T, Reverse<Instant>>>,
    event: Event,
}

impl<T: Hash + Eq> DelayQueue<T> {
    pub fn new() -> Self {
        Self {
            priority_queue: Mutex::new(PriorityQueue::new()),
            event: Event::new(),
        }
    }
    /// inserts `item` with delay
    pub fn insert(&self, item: T, emit_time: Instant) {
        let _ = self.priority_queue.lock().push(item, Reverse(emit_time));
        // eprintln!("notifying!");
        self.event.notify(1);
    }

    /// *blocks* until the item with the shortest delay is ready, then returns it
    pub async fn pop(&self) -> T {
        loop {
            // first, we try to pop out the first one
            let (val, Reverse(earliest_pop)) = self
                .event
                .wait_until(|| self.priority_queue.lock().pop())
                .await;
            let now = Instant::now();
            if earliest_pop <= now {
                return val;
            }

            // otherwise, we put it back and wait until *at most* the correct time
            self.priority_queue.lock().push(val, Reverse(earliest_pop));
            smol::Timer::at(earliest_pop)
                .race(self.wait_till_earlier(earliest_pop))
                .await;
        }
    }

    async fn wait_till_earlier(&self, earliest_pop: Instant) -> Instant {
        self.event
            .wait_until(|| {
                self.priority_queue.lock().peek().and_then(|(_, until)| {
                    if until.0 < earliest_pop {
                        Some(until.0.clone())
                    } else {
                        None
                    }
                })
            })
            .await
    }
}
