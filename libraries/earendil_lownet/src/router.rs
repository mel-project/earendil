use std::sync::{Arc, RwLock};

use async_channel::Sender;

use haiyuu::{Mailbox, Process};

use crate::{Datagram, link_table::LinkTable, topology::Topology};

pub struct Router {
    pub topo: Topology,
    pub table: Arc<RwLock<LinkTable>>,
    pub send_incoming: Sender<Datagram>,
}

impl Process for Router {
    type Message = Datagram;
    type Output = ();

    async fn run(&mut self, mailbox: &mut Mailbox<Self>) -> Self::Output {
        loop {
            let mut dg = mailbox.recv().await;

            if self.table.read().unwrap().is_local_addr(dg.dest_addr) {
                tracing::debug!(
                    dest = display(dg.dest_addr),
                    "datagram addressed to myself!"
                );
                let _ = self.send_incoming.try_send(dg);
                continue;
            }

            if dg.ttl == 0 {
                tracing::debug!(
                    dest = display(dg.dest_addr),
                    "dropping a datagram with zero ttl"
                );
                continue;
            }
            dg.ttl -= 1;

            if let Some(neigh) = self.table.read().unwrap().neigh_link(dg.dest_addr) {
                tracing::debug!(dest = display(dg.dest_addr), "destination is neighbor");
                let _ = neigh.send_or_drop(dg);
            } else {
                // we need routing here. find the closest *relay* to the destination.
                // todo: some form of caching would be nice
                let table = self.table.read().unwrap();

                let best_neigh =
                    table
                        .neighbors()
                        .filter(|n| n.client_id == 0)
                        .min_by_key(|neigh| {
                            self.topo
                                .graph()
                                .read()
                                .unwrap()
                                .find_shortest_path(neigh.relay, dg.dest_addr.relay)
                                .map(|s| s.len())
                                .unwrap_or(usize::MAX)
                        });
                if let Some(neigh) = best_neigh {
                    tracing::debug!(dest = display(dg.dest_addr), "routing through a neighbor");
                    let _ = table.neigh_link(neigh).unwrap().send_or_drop(dg);
                } else {
                    tracing::warn!(dest = display(dg.dest_addr), "cannot route to destination")
                }
            }
        }
    }
}
