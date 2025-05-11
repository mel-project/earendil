mod auth;
mod in_link;
mod link;
mod link_table;
mod out_link;
mod router;
mod types;

use std::sync::{Arc, RwLock};

use async_channel::Receiver;
use async_task::Task;
use earendil_topology::RelayGraph;
use futures_concurrency::future::{FutureExt, FutureGroup};
use futures_util::StreamExt;
use haiyuu::{Handle, Process};
use in_link::in_link;
use link_table::LinkTable;
use out_link::out_link;
use router::Router;
pub use types::*;

pub struct LowNet {
    router: Handle<Router>,
    recv_incoming: Receiver<Datagram>,

    _task: Task<()>,
}

pub struct LowNetConfig {
    pub in_links: Vec<InLinkConfig>,
    pub out_links: Vec<OutLinkConfig>,
    pub identity: NodeIdentity,
}

impl LowNet {
    pub fn new(cfg: LowNetConfig) -> Self {
        let table = Arc::new(RwLock::new(LinkTable::default()));
        let graph = Arc::new(RwLock::new(RelayGraph::new()));
        let (send_incoming, recv_incoming) = async_channel::bounded(100);
        let router = Router {
            graph,
            table: table.clone(),
            send_incoming,
        }
        .spawn_smolscale();
        let _task = {
            let mut in_group = FutureGroup::new();
            for link in cfg.in_links.iter() {
                in_group.insert(in_link(
                    cfg.identity,
                    link.clone(),
                    table.clone(),
                    router.clone(),
                ));
            }
            let mut out_group = FutureGroup::new();
            for link in cfg.out_links.iter() {
                out_group.insert(out_link(
                    cfg.identity,
                    link.clone(),
                    table.clone(),
                    router.clone(),
                ));
            }
            smolscale::spawn(async move {
                in_group
                    .collect::<Vec<_>>()
                    .join(out_group.collect::<Vec<_>>())
                    .await;
            })
        };

        Self {
            router,
            recv_incoming,
            _task,
        }
    }
}
