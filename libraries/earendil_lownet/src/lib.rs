mod auth;

mod in_link;
mod link;
mod link_table;
mod out_link;
mod router;
mod topology;
mod types;
use std::sync::{Arc, RwLock};
pub use topology::Topology;

use async_channel::Receiver;
use async_task::Task;

use futures_concurrency::future::{FutureExt, FutureGroup};
use futures_util::StreamExt;
use haiyuu::{Handle, Process};
use in_link::in_link;
use link_table::LinkTable;
use out_link::out_link;
use router::Router;

pub use types::*;

/// A low-level networking abstraction for managing communication between nodes.
///
/// The `LowNet` struct represents a node in the network and provides methods for
/// sending and receiving datagrams, as well as accessing the network topology.
/// # Example
///
/// ```
/// use earendil_lownet::{LowNet, LowNetConfig, InLinkConfig, OutLinkConfig, NodeIdentity};
///
/// let config = LowNetConfig {
///     in_links: vec![],
///     out_links: vec![],
///     identity: NodeIdentity::ClientBearer(100),
/// };
///
/// let lownet = LowNet::new(config);
/// ```
pub struct LowNet {
    router: Handle<Router>,
    recv_incoming: Receiver<Datagram>,
    topology: Topology,
    _task: Task<()>,
}

pub struct LowNetConfig {
    pub in_links: Vec<InLinkConfig>,
    pub out_links: Vec<OutLinkConfig>,
    pub identity: NodeIdentity,
}

impl LowNet {
    /// Creates a new `LowNet` instance with the given configuration.
    pub fn new(cfg: LowNetConfig) -> Self {
        let table = Arc::new(RwLock::new(LinkTable::default()));

        let (send_incoming, recv_incoming) = async_channel::bounded(100);
        let topo = Topology::new(cfg.identity);
        let router = Router {
            topo: topo.clone(),
            table: table.clone(),
            send_incoming,
        }
        .spawn_smolscale();
        let _task = {
            let mut in_group = FutureGroup::new();
            for link in cfg.in_links.iter() {
                in_group.insert(in_link(
                    topo.clone(),
                    link.clone(),
                    table.clone(),
                    router.clone(),
                ));
            }
            let mut out_group = FutureGroup::new();
            for link in cfg.out_links.iter() {
                out_group.insert(out_link(
                    topo.clone(),
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
            topology: topo,
            _task,
        }
    }

    /// Receives an incoming datagram from the network.
    ///
    /// This method will block until a datagram is available.
    pub async fn recv(&self) -> Datagram {
        self.recv_incoming.recv().await.expect("router died")
    }

    /// Sends a datagram to the network.
    pub async fn send(&self, dg: Datagram) {
        self.router.send(dg).await.expect("router died")
    }

    /// Returns a clone of the current network topology.
    pub async fn topology(&self) -> Topology {
        self.topology.clone()
    }
}
