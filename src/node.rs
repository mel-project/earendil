use crate::{
    link_node::{LinkConfig, LinkNode},
    n2r_node::{N2rConfig, N2rNode},
    v2h_node::{V2hConfig, V2hNode},
    ConfigFile,
};

pub struct Node {}

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

    pub fn v2h(&self) -> &V2hNode {
        todo!()
    }
}
