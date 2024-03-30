use ahash::AHashMap;

#[derive(Clone)]
pub struct Reorderer<T: Clone> {
    pkts: AHashMap<u64, T>,
    min: u64,
}

impl<T: Clone> Default for Reorderer<T> {
    fn default() -> Self {
        Reorderer {
            pkts: AHashMap::default(),
            min: 0,
        }
    }
}
impl<T: Clone> Reorderer<T> {
    /// Inserts an item into the reorderer. Returns true iff the item is accepted or has been accepted in the past.
    pub fn insert(&mut self, seq: u64, item: T) -> bool {
        log::trace!("reorder seq={}, min={}", seq, self.min);
        if seq >= self.min && seq <= self.min + 20000 {
            if self.pkts.insert(seq, item).is_some() {
                log::debug!("spurious in pending of {} received", seq);
            }
            true
        } else {
            log::debug!("spurious in past of (seq={}, min={})", seq, self.min);
            // if less than min, we still accept
            seq < self.min
        }
    }
    pub fn take(&mut self) -> Vec<(u64, T)> {
        let mut output = Vec::with_capacity(self.pkts.len());
        for idx in self.min.. {
            if let Some(item) = self.pkts.remove(&idx) {
                output.push((idx, item.clone()));
                self.min = idx + 1;
            } else {
                break;
            }
        }
        output
    }
}
