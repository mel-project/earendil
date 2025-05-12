use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use async_io::Timer;
use async_task::Task;
use earendil_packet::crypt::DhSecret;
use earendil_topology::{IdentityDescriptor, RelayGraph};

use crate::NodeIdentity;

#[derive(Clone)]
pub struct Topology {
    graph: Arc<RwLock<RelayGraph>>,
    identity: NodeIdentity,
    dh_secret: DhSecret,

    _task: Arc<Task<()>>,
}

impl Topology {
    pub fn new(identity: NodeIdentity) -> Self {
        let graph = Arc::new(RwLock::new(RelayGraph::new()));
        let dh_secret = DhSecret::generate();
        let _task = smolscale::spawn({
            let graph = graph.clone();
            let dh_secret = dh_secret.clone();
            async move {
                if let NodeIdentity::Relay(relay) = identity {
                    loop {
                        let id = IdentityDescriptor::new(&relay, &dh_secret, None);
                        graph.write().unwrap().insert_identity(id).unwrap();
                        Timer::after(Duration::from_secs(10)).await;
                    }
                }
            }
        });
        Self {
            graph,
            identity,
            dh_secret,
            _task: Arc::new(_task),
        }
    }

    pub fn graph(&self) -> &RwLock<RelayGraph> {
        &self.graph
    }

    pub fn identity(&self) -> NodeIdentity {
        self.identity
    }

    pub fn relay_identity_descriptor(&self) -> Option<IdentityDescriptor> {
        if let NodeIdentity::Relay(relay) = self.identity {
            Some(IdentityDescriptor::new(&relay, &self.dh_secret, None))
        } else {
            None
        }
    }

    pub fn dh_secret(&self) -> &DhSecret {
        &self.dh_secret
    }
}
