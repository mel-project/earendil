use dashmap::DashMap;
use std::collections::VecDeque;
use std::ops::Range;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_CAPACITY: usize = 500;

#[derive(Debug, Clone)]
pub struct StatsGatherer {
    // key is a neighbor ID + direction (e.g., "neighbor_1|up")
    // value is a VecDeque of (unix_timestamp_millis, stats_value)
    inner: DashMap<String, VecDeque<(i64, f64)>>,
    capacity: usize,
}

impl Default for StatsGatherer {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

impl StatsGatherer {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: DashMap::new(),
            capacity,
        }
    }

    pub fn insert(&self, key: &str, value: f64) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as i64;

        self.inner
            .entry(key.to_string())
            .and_modify(|deque| {
                if deque.len() >= self.capacity {
                    deque.pop_front();
                }
                deque.push_back((timestamp, value));
            })
            .or_insert_with(|| {
                let mut deque = VecDeque::with_capacity(self.capacity);
                deque.push_back((timestamp, value));
                deque
            });
    }

    pub fn get(&self, key: &str, range: Range<i64>) -> Vec<(i64, f64)> {
        self.inner
            .get(key)
            .map(|deque| {
                deque
                    .iter()
                    .filter(|(timestamp, _)| range.contains(timestamp))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    // get the current size of a specific key's data
    pub fn get_size(&self, key: &str) -> usize {
        self.inner.get(key).map(|deque| deque.len()).unwrap_or(0)
    }
}
