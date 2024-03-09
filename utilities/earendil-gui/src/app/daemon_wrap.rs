use std::{net::SocketAddr, sync::Arc};

use earendil::{control_protocol::ControlClient, daemon::Daemon};
use earendil_crypt::RelayIdentitySecret;

#[derive(Clone)]
pub enum DaemonWrap {
    Remote(SocketAddr),
    Embedded(Arc<Daemon>),
}

impl DaemonWrap {
    /// Obtain the control-protocol handle for this particular kind of daemon.
    pub fn control(&self) -> ControlClient {
        match self {
            DaemonWrap::Remote(rem) => {
                ControlClient::from(nanorpc_http::client::HttpRpcTransport::new(*rem))
            }
            DaemonWrap::Embedded(emb) => emb.control_client(),
        }
    }

    pub fn global_sk(&self) -> Option<RelayIdentitySecret> {
        match self {
            DaemonWrap::Remote(_) => None, // todo: add control method?
            DaemonWrap::Embedded(d) => Some(d.identity()),
        }
    }
}
