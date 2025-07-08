use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use async_io::Timer;
use async_task::Task;

use bytes::Bytes;
use earendil_crypt::DhSecret;
use earendil_topology::{IdentityDescriptor, IdentityDescriptorBuilder, RelayGraph};

use crate::NodeIdentity;

#[derive(Clone)]
pub struct Topology {
    graph: Arc<RwLock<RelayGraph>>,
    identity: NodeIdentity,
    dh_secret: DhSecret,
    metadata: BTreeMap<String, Bytes>,

    _task: Arc<Task<()>>,
}

impl Topology {
    pub fn new(identity: NodeIdentity, metadata: BTreeMap<String, Bytes>) -> Self {
        tracing::debug!(
            identity = debug(identity),
            metadata = debug(&metadata),
            "creating new topology"
        );
        let graph = Arc::new(RwLock::new(RelayGraph::new()));
        let dh_secret = DhSecret::generate();
        let _task = smolscale::spawn({
            let graph = graph.clone();
            let dh_secret = dh_secret.clone();
            let metadata = metadata.clone();
            async move {
                if let NodeIdentity::Relay(relay) = identity {
                    loop {
                        let id = IdentityDescriptorBuilder::new(&relay, &dh_secret)
                            .add_metadata_multi(metadata.clone())
                            .build();
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
            metadata,
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
            Some(
                IdentityDescriptorBuilder::new(&relay, &self.dh_secret)
                    .add_metadata_multi(self.metadata.clone())
                    .build(),
            )
        } else {
            None
        }
    }

    pub fn dh_secret(&self) -> &DhSecret {
        &self.dh_secret
    }
}
