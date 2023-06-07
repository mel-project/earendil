use std::time::{Duration, Instant};

use dashmap::DashMap;
use earendil_packet::{Fingerprint, RawPacket};
use smol::{
    channel::{Receiver, Sender},
    Task,
};

use super::connection::Connection;

/// A table of the neighbors of the current node
#[allow(clippy::type_complexity)]
pub struct NeighTable {
    table: DashMap<Fingerprint, (Connection, Option<Instant>, Task<anyhow::Result<()>>)>,
    send_incoming: Sender<RawPacket>,
    recv_incoming: Receiver<RawPacket>,
}

impl NeighTable {
    /// Create a new NeighTable.
    pub fn new() -> Self {
        let (send_incoming, recv_incoming) = smol::channel::bounded(1);
        Self {
            table: Default::default(),
            send_incoming,
            recv_incoming,
        }
    }

    /// Receive the next incoming packet from neighbors.
    pub async fn recv_raw_packet(&self) -> RawPacket {
        self.recv_incoming.recv().await.unwrap()
    }

    /// Insert a fingerprint-connection mapping with a TTL.
    pub fn insert(&self, fingerprint: Fingerprint, connection: Connection, ttl: Duration) {
        self.insert_inner(fingerprint, connection, Some(ttl))
    }

    /// Insert a fingerprint-connection mapping with no expiry time.
    pub fn insert_pinned(&self, fingerprint: Fingerprint, connection: Connection) {
        self.insert_inner(fingerprint, connection, None)
    }

    fn insert_inner(
        &self,
        fingerprint: Fingerprint,
        connection: Connection,
        ttl: Option<Duration>,
    ) {
        let expiry = ttl.map(|ttl| Instant::now() + ttl);
        let send_incoming = self.send_incoming.clone();
        self.table.insert(
            fingerprint,
            (
                connection.clone(),
                expiry,
                smolscale::spawn(async move {
                    loop {
                        let pkt = connection.recv_raw_packet().await?;
                        send_incoming.send(pkt).await?;
                    }
                }),
            ),
        );
    }

    /// Lookup a connection by its fingerprint.
    pub fn lookup(&self, fingerprint: &Fingerprint) -> Option<Connection> {
        self.table
            .get(fingerprint)
            .map(|entry| entry.value().0.clone())
    }

    /// Returns all the connections.
    pub fn all_neighs(&self) -> Vec<Connection> {
        self.table.iter().map(|s| s.0.clone()).collect()
    }

    /// Remove all expired entries from the table.
    pub fn garbage_collect(&self) {
        let now = Instant::now();
        self.table
            .retain(|_fingerprint, (_connection, expiry, _)| match expiry {
                Some(instant) => *instant > now,
                None => true,
            });
    }
}
