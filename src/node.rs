use earendil_crypt::{HavenEndpoint, HavenIdentitySecret, RelayFingerprint};

use crate::{
    config::ConfigFile,
    link_node::{LinkConfig, LinkNode},
    n2r_node::{N2rConfig, N2rNode},
    v2h_node::{HavenListener, HavenPacketConn, PooledListener, PooledVisitor, V2hConfig, V2hNode},
};

/// The public interface to the whole Earendil system.
pub struct Node {
    v2h: V2hNode,
}

impl Node {
    pub fn new(config: ConfigFile) -> anyhow::Result<Self> {
        let link = LinkNode::new(LinkConfig {
            in_routes: config.in_routes.clone(),
            out_routes: config.out_routes.clone(),
            my_idsk: if let Some(id) = config.identity {
                Some(id.actualize_relay()?)
            } else {
                None
            },
        });
        let n2r = N2rNode::new(link, N2rConfig {});
        let _v2h = V2hNode::new(n2r, V2hConfig {});

        // start loops for handling socks5, etc, etc

        todo!()
    }

    /// Creates a low-level, unreliable packet connection.
    pub async fn packet_connect(&self, dest: HavenEndpoint) -> anyhow::Result<HavenPacketConn> {
        self.v2h.packet_connect(dest).await
    }

    /// Creates a low-level, unreliable packet listener.
    pub async fn packet_listen(
        &self,
        identity: HavenIdentitySecret,
        port: u16,
        rendezvous: RelayFingerprint,
    ) -> anyhow::Result<HavenListener> {
        self.v2h.packet_listen(identity, port, rendezvous).await
    }

    /// Creates a new pooled visitor. Under Earendil's anonymity model, each visitor should be unlinkable to any other visitor, but streams created within each visitor are linkable to the same haven each other by the haven (though not by the network).
    pub async fn pooled_visitor(&self) -> PooledVisitor {
        self.v2h.pooled_visitor().await
    }

    /// Creates a new pooled listener.
    pub async fn pooled_listen(
        &self,
        identity: HavenIdentitySecret,
        port: u16,
        rendezvous: RelayFingerprint,
    ) -> anyhow::Result<PooledListener> {
        self.v2h.pooled_listen(identity, port, rendezvous).await
    }
}
