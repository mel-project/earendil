use std::sync::{Arc, Weak};

use dashmap::DashMap;
use earendil_crypt::RelayFingerprint;
use earendil_topology::RelayGraph;
use parking_lot::RwLock;

use super::NeighborId;

/// A graph of the network. Similar to RelayGraph, but concurrency-enabled and augmented with information about where *we* are in the graph and what live neighbors we have.
#[derive(Clone)]
pub struct NetGraph {
    relay_graph: Arc<RwLock<RelayGraph>>,
    live_neighbors: Arc<DashMap<NeighborId, usize>>,
    myself: NeighborId,
}

impl NetGraph {
    /// Creates a new NetGraph.
    pub fn new(myself: NeighborId) -> Self {
        Self {
            relay_graph: Arc::new(RwLock::new(RelayGraph::new())),
            live_neighbors: Arc::new(DashMap::new()),
            myself,
        }
    }

    /// Obtains a guard that marks the neighbor as live as long as it lives.
    pub fn neighbor_guard(&self, id: NeighborId) -> NeighborGuard {
        let mut count = self.live_neighbors.entry(id).or_default();
        *count += 1;
        NeighborGuard {
            live_neighbors: Arc::downgrade(&self.live_neighbors),
            this_id: id,
        }
    }

    /// Obtains a list of *usable* neighbor relays, which must be both live and within the relay graph.
    pub fn usable_relay_neighbors(&self) -> Vec<RelayFingerprint> {
        self.live_neighbors
            .iter()
            .filter_map(|r| {
                let id = r.key();
                if let NeighborId::Relay(id) = id {
                    if self.relay_graph.read().identity(id).is_some() {
                        Some(*id)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect()
    }

    /// Modify the underlying relay graph.
    pub fn modify_graph<T>(&self, f: impl FnOnce(&mut RelayGraph) -> T) -> T {
        let mut inner = self.relay_graph.write();
        f(&mut inner)
    }

    /// Read the underlying relay graph.
    pub fn read_graph<T>(&self, f: impl FnOnce(&RelayGraph) -> T) -> T {
        let inner = self.relay_graph.read();
        f(&inner)
    }
}

pub struct NeighborGuard {
    live_neighbors: Weak<DashMap<NeighborId, usize>>,
    this_id: NeighborId,
}

impl Drop for NeighborGuard {
    fn drop(&mut self) {
        if let Some(live_neighbors) = self.live_neighbors.upgrade() {
            let entry = live_neighbors.entry(self.this_id);
            match entry {
                dashmap::mapref::entry::Entry::Occupied(mut occupied_entry) => {
                    let should_die = {
                        let inner = occupied_entry.get_mut();
                        *inner -= 1;
                        *inner == 0
                    };
                    if should_die {
                        occupied_entry.remove();
                    }
                }
                dashmap::mapref::entry::Entry::Vacant(_) => {
                    panic!("already vacant when NeighborGuard is dropped, this should never happen")
                }
            }
        }
    }
}
