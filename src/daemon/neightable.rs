use std::time::{Duration, Instant};

use dashmap::DashMap;
use earendil_packet::Fingerprint;

use super::connection::Connection;

/// A table of the neighbors of the current node.
pub struct NeighTable {
    table: DashMap<Fingerprint, (Connection, Option<Instant>)>,
}

impl NeighTable {
    /// Create a new NeighTable.
    pub fn new() -> Self {
        Self {
            table: Default::default(),
        }
    }

    /// Insert a fingerprint-connection mapping with a TTL.
    pub fn insert(&self, fingerprint: Fingerprint, connection: Connection, ttl: Duration) {
        let expiry = Instant::now() + ttl;
        self.table.insert(fingerprint, (connection, Some(expiry)));
    }

    /// Insert a fingerprint-connection mapping with no expiry time.
    pub fn insert_pinned(&self, fingerprint: Fingerprint, connection: Connection) {
        self.table.insert(fingerprint, (connection, None));
    }

    /// Lookup a connection by its fingerprint.
    pub fn lookup(&self, fingerprint: &Fingerprint) -> Option<Connection> {
        self.table
            .get(fingerprint)
            .map(|entry| entry.value().0.clone())
    }

    /// Remove all expired entries from the table.
    pub fn garbage_collect(&self) {
        let now = Instant::now();
        self.table
            .retain(|_fingerprint, (_connection, expiry)| match expiry {
                Some(instant) => *instant > now,
                None => true,
            });
    }
}
