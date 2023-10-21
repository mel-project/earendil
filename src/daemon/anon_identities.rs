use std::time::Duration;

use earendil_crypt::IdentitySecret;
use earendil_packet::crypt::OnionSecret;
use moka::sync::Cache;

pub struct AnonIdentities {
    map: Cache<String, (IdentitySecret, OnionSecret)>,
}

impl AnonIdentities {
    pub fn new() -> Self {
        let map = Cache::builder()
            .max_capacity(100_000)
            .time_to_idle(Duration::from_secs(3600))
            .build();
        Self { map }
    }

    pub fn get(&mut self, id: &str) -> (IdentitySecret, OnionSecret) {
        let ret = self
            .map
            .get_with_by_ref(id, || (IdentitySecret::generate(), OnionSecret::generate()));
        ret
    }
}
