use std::time::Duration;

use anyhow::Context;
use async_io::Timer;
use async_stdcode::{StdcodeReader, StdcodeWriter};
use earendil_topology::{AdjacencyDescriptor, IdentityDescriptor};
use futures_concurrency::future::Race;
use futures_util::AsyncReadExt;
use haiyuu::{Process, WeakHandle};
use serde::{Deserialize, Serialize};

use crate::{
    Datagram, NodeAddr, NodeIdentity, router::Router, topology::Topology,
};

pub struct Link {
    pub link_pipe: Box<dyn sillad::Pipe>,
    pub gossip_pipe: Box<dyn sillad::Pipe>,
    pub neigh_addr: NodeAddr,
    pub topo: Topology,
    pub router: WeakHandle<Router>,
    pub on_drop: Box<dyn FnOnce() + Send + 'static>,
}

impl Drop for Link {
    fn drop(&mut self) {
        let mut lala: Box<dyn FnOnce() + Send + 'static> = Box::new(|| {});
        std::mem::swap(&mut self.on_drop, &mut lala);
        lala()
    }
}

impl Process for Link {
    type Message = Datagram;
    type Output = ();
    const MAILBOX_CAP: usize = 100;

    async fn run(&mut self, mailbox: &mut haiyuu::Mailbox<Self>) -> Self::Output {
        let link_loop = async {
            let (read, write) = (&mut self.link_pipe).split();
            let (mut read, mut write) = (StdcodeReader::new(read), StdcodeWriter::new(write));
            let read_loop = async {
                loop {
                    let dg: Datagram = read.read().await?;
                    self.router.send(dg).await?;
                }
            };
            let write_loop = async {
                loop {
                    let dg = mailbox.recv().await;
                    write.write(dg).await?;
                }
            };
            let res: anyhow::Result<()> = (read_loop, write_loop).race().await;
            res
        };
        let gossip_loop = async {
            let my_id = if let NodeIdentity::Relay(my_id) = self.topo.identity() {
                Some(my_id)
            } else {
                None
            };

            let (read, write) = (&mut self.gossip_pipe).split();
            let (mut read, mut write) = (StdcodeReader::new(read), StdcodeWriter::new(write));

            // up loop actually sends stuff
            let up_loop = async {
                loop {
                    let msg = {
                        let graph = self.topo.graph().read().unwrap();
                        graph.random_adjacency().and_then(|adj| {
                            Some(GossipMsg::PushAdjacency(
                                graph.identity(adj.left)?,
                                adj.clone(),
                                graph.identity(adj.right)?,
                            ))
                        })
                    };
                    if let Some(msg) = msg {
                        tracing::debug!(
                            neigh_addr = display(self.neigh_addr),
                            msg = debug(&msg),
                            "sending gossip msg"
                        );
                        write.write(msg).await?;
                    } else {
                        tracing::warn!(
                            neigh_addr = display(self.neigh_addr),
                            "nothing to gossip yet"
                        )
                    }
                    Timer::after(Duration::from_secs(1)).await;
                }
            };

            let dn_loop = async {
                loop {
                    let msg: GossipMsg = read.read().await?;
                    if self.neigh_addr.client_id != 0 {
                        anyhow::bail!("clients should not send any gossip messages")
                    }
                    match msg {
                        GossipMsg::IncompleteAdjacency(
                            mut adjacency_descriptor,
                            identity_descriptor,
                        ) => {
                            identity_descriptor.verify()?;
                            let my_id = my_id
                                .context("cannot process incomplete adjacency as a non-relay")?;
                            if identity_descriptor.identity_pk.fingerprint()
                                != self.neigh_addr.relay
                            {
                                anyhow::bail!(
                                    "got an identity descriptor not from the declared neighbor"
                                )
                            }
                            if !(adjacency_descriptor.left == self.neigh_addr.relay
                                && adjacency_descriptor.left < my_id.public().fingerprint()
                                && adjacency_descriptor.right == my_id.public().fingerprint())
                            {
                                anyhow::bail!("got the wrong adjacency descriptor")
                            }
                            let signature = my_id.sign(adjacency_descriptor.to_sign().as_bytes());
                            adjacency_descriptor.right_sig = signature;

                            let mut graph = self.topo.graph().write().unwrap();
                            graph.insert_identity(identity_descriptor)?;
                            graph.insert_adjacency(adjacency_descriptor)?;
                        }

                        GossipMsg::PushAdjacency(
                            identity_descriptor,
                            adjacency_descriptor,
                            identity_descriptor1,
                        ) => {
                            let mut graph = self.topo.graph().write().unwrap();
                            graph.insert_identity(identity_descriptor)?;
                            graph.insert_identity(identity_descriptor1)?;
                            graph.insert_adjacency(adjacency_descriptor)?;
                        }
                    }
                }
            };
            (up_loop, dn_loop).race().await
        };
        let res: anyhow::Result<()> = (link_loop, gossip_loop).race().await;
        if let Err(err) = res {
            tracing::debug!(err = debug(err), "link died")
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
enum GossipMsg {
    IncompleteAdjacency(AdjacencyDescriptor, IdentityDescriptor),

    PushAdjacency(IdentityDescriptor, AdjacencyDescriptor, IdentityDescriptor),
}
