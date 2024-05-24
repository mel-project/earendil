use moka::sync::{Cache, CacheBuilder};
use std::{hash::Hash, time::Duration};

pub struct Bicache<K, V> {
    k_to_v: Cache<K, V>,
    v_to_k: Cache<V, K>,
}

impl<
        K: Clone + Eq + Hash + Send + Sync + 'static,
        V: Clone + Eq + Hash + Send + Sync + 'static,
    > Bicache<K, V>
{
    pub fn new(ttl: u64) -> Self {
        Self {
            k_to_v: CacheBuilder::default()
                .time_to_live(Duration::from_secs(ttl))
                .build(),
            v_to_k: CacheBuilder::default()
                .time_to_live(Duration::from_secs(ttl))
                .build(),
        }
    }

    pub fn insert(&self, k: K, v: V) {
        self.k_to_v.insert(k.clone(), v.clone());
        self.v_to_k.insert(v, k);
    }

    pub fn get_by_key(&self, k: &K) -> Option<V> {
        self.k_to_v.get(k)
    }

    pub fn get_by_value(&self, v: &V) -> Option<K> {
        self.v_to_k.get(v)
    }
}
