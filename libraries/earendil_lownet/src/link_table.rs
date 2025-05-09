use std::collections::hash_map::Entry;

use ahash::AHashMap;

use haiyuu::Handle;
use rand::seq::IndexedRandom;

use crate::{NodeAddr, link::Link};

pub struct LinkTable {
    id_to_link: AHashMap<u64, (NodeAddr, Handle<Link>)>,
    addr_to_id: AHashMap<NodeAddr, Vec<u64>>,
}

impl LinkTable {
    pub fn insert(&mut self, addr: NodeAddr, id: u64, handle: Handle<Link>) {
        if self.id_to_link.contains_key(&id) {
            panic!("duplicate insertion into linktable")
        }
        self.id_to_link.insert(id, (addr, handle));
        self.addr_to_id.entry(addr).or_default().push(id);
    }

    pub fn remove(&mut self, id: u64) {
        if let Some((addr, _)) = self.id_to_link.remove(&id) {
            if let Entry::Occupied(mut entry) = self.addr_to_id.entry(addr) {
                entry.get_mut().retain(|v| *v != id);
                if entry.get().is_empty() {
                    entry.remove();
                }
            }
        }
    }

    pub fn get_link(&self, addr: NodeAddr) -> Option<Handle<Link>> {
        let v = self.addr_to_id.get(&addr)?;
        // TODO something more sophisticated than random selection
        let id = v.choose(&mut rand::rng()).copied()?;
        Some(self.id_to_link.get(&id)?.1.clone())
    }

    pub fn neighbors(&self) -> impl Iterator<Item = NodeAddr> + '_ {
        self.addr_to_id.keys().copied()
    }
}
