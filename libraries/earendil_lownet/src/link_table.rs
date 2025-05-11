use std::{collections::hash_map::Entry, sync::atomic::AtomicU64};

use ahash::AHashMap;

use haiyuu::Handle;
use rand::seq::IndexedRandom;

use crate::{NodeAddr, link::Link};

#[derive(Default)]
pub struct LinkTable {
    id_to_link: AHashMap<u64, (NodeAddr, NodeAddr, Handle<Link>)>,
    local_addr_to_id: AHashMap<NodeAddr, Vec<u64>>,
    neigh_addr_to_id: AHashMap<NodeAddr, Vec<u64>>,
}

impl LinkTable {
    pub fn next_id() -> u64 {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);

        NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    pub fn insert(
        &mut self,
        local_addr: NodeAddr,
        neigh_addr: NodeAddr,
        id: u64,
        handle: Handle<Link>,
    ) {
        if self.id_to_link.contains_key(&id) {
            panic!("duplicate insertion into linktable")
        }
        self.id_to_link.insert(id, (local_addr, neigh_addr, handle));
        self.neigh_addr_to_id
            .entry(neigh_addr)
            .or_default()
            .push(id);
        self.local_addr_to_id
            .entry(local_addr)
            .or_default()
            .push(id);
    }

    pub fn remove(&mut self, id: u64) {
        if let Some((local_addr, remote_addr, _)) = self.id_to_link.remove(&id) {
            if let Entry::Occupied(mut entry) = self.local_addr_to_id.entry(local_addr) {
                entry.get_mut().retain(|v| *v != id);
                if entry.get().is_empty() {
                    entry.remove();
                }
            }
            if let Entry::Occupied(mut entry) = self.neigh_addr_to_id.entry(remote_addr) {
                entry.get_mut().retain(|v| *v != id);
                if entry.get().is_empty() {
                    entry.remove();
                }
            }
        }
    }

    pub fn neigh_link(&self, neigh_addr: NodeAddr) -> Option<Handle<Link>> {
        let v = self.neigh_addr_to_id.get(&neigh_addr)?;
        // TODO something more sophisticated than random selection
        let id = v.choose(&mut rand::rng()).copied()?;
        Some(self.id_to_link.get(&id)?.2.clone())
    }

    pub fn neighbors(&self) -> impl Iterator<Item = NodeAddr> + '_ {
        self.neigh_addr_to_id.keys().copied()
    }

    pub fn local_addrs(&self) -> impl Iterator<Item = NodeAddr> + '_ {
        self.local_addr_to_id.keys().copied()
    }

    pub fn is_local_addr(&self, addr: NodeAddr) -> bool {
        self.local_addr_to_id.contains_key(&addr)
    }
}
