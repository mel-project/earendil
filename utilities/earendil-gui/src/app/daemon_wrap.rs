use std::{net::SocketAddr, sync::Arc};

use earendil::{control_protocol::ControlClient, NeighborId, Node};

#[derive(Clone)]
pub enum DaemonWrap {
    Remote(SocketAddr),
    Embedded(Arc<Node>),
}

impl DaemonWrap {
    /// Obtain the control-protocol handle for this particular kind of daemon.
    pub fn control(&self) -> ControlClient {
        match self {
            DaemonWrap::Remote(rem) => {
                ControlClient::from(nanorpc_http::client::HttpRpcTransport::new_with_proxy(
                    rem.to_string(),
                    nanorpc_http::client::Proxy::Direct,
                ))
            }
            DaemonWrap::Embedded(emb) => emb.control_client(),
        }
    }

    pub fn identity(&self) -> NeighborId {
        todo!()
    }

    pub fn check_dead(&self) -> anyhow::Result<()> {
        match self {
            DaemonWrap::Remote(_) => todo!(),
            DaemonWrap::Embedded(daemon) => daemon.check_dead(),
        }
    }
}
