use std::time::{Duration, Instant};

use dashmap::DashMap;
use earendil_crypt::Fingerprint;
use earendil_packet::RawPacket;
use smol::channel::{Receiver, Sender};
use smolscale::immortal::Immortal;

use super::link_connection::LinkConnection;

/// A table of the neighbors of the current node
#[allow(clippy::type_complexity)]
pub struct NeighTable {
    table: DashMap<Fingerprint, (LinkConnection, Option<Instant>, Immortal)>,
    send_incoming: Sender<(Fingerprint, RawPacket)>,
    recv_incoming: Receiver<(Fingerprint, RawPacket)>,
}

impl Default for NeighTable {
    fn default() -> Self {
        Self::new()
    }
}

impl NeighTable {
    /// Create a new NeighTable.
    pub fn new() -> Self {
        let (send_incoming, recv_incoming) = smol::channel::bounded(100);
        Self {
            table: Default::default(),
            send_incoming,
            recv_incoming,
        }
    }

    /// Receive the next incoming packet from neighbors.
    pub async fn recv_raw_packet(&self) -> (Fingerprint, RawPacket) {
        self.recv_incoming.recv().await.unwrap()
    }

    /// Inject a packet *as if* it came from another node.
    pub async fn inject_asif_incoming(&self, last_hop: Fingerprint, pkt: RawPacket) {
        let _ = self.send_incoming.send((last_hop, pkt)).await;
    }

    /// Insert a fingerprint-connection mapping with a TTL.
    pub fn insert(&self, fingerprint: Fingerprint, connection: LinkConnection, ttl: Duration) {
        self.insert_inner(fingerprint, connection, Some(ttl))
    }

    /// Insert a fingerprint-connection mapping with no expiry time.
    pub fn insert_pinned(&self, fingerprint: Fingerprint, connection: LinkConnection) {
        self.insert_inner(fingerprint, connection, None)
    }

    fn insert_inner(
        &self,
        fingerprint: Fingerprint,
        connection: LinkConnection,
        ttl: Option<Duration>,
    ) {
        let expiry = ttl.map(|ttl| Instant::now() + ttl);
        let send_incoming = self.send_incoming.clone();
        let remote_fp = connection.remote_idpk.fingerprint();
        self.table.insert(
            fingerprint,
            (
                connection.clone(),
                expiry,
                Immortal::spawn(async move {
                    loop {
                        let pkt = connection.recv_raw_packet().await;
                        let _ = send_incoming.send((remote_fp, pkt)).await;
                    }
                }),
            ),
        );
    }

    /// Lookup a connection by its fingerprint.
    pub fn lookup(&self, fingerprint: &Fingerprint) -> Option<LinkConnection> {
        self.table
            .get(fingerprint)
            .map(|entry| entry.value().0.clone())
    }

    /// Returns all the connections.
    pub fn all_neighs(&self) -> Vec<LinkConnection> {
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
