use std::net::SocketAddr;

use earendil::{control_protocol::ControlClient, daemon::Daemon};
use earendil_crypt::IdentitySecret;

pub enum DaemonWrap {
    Remote(SocketAddr),
    Embedded(Daemon),
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

    pub fn global_sk(&self) -> Option<IdentitySecret> {
        match self {
            DaemonWrap::Remote(_) => None, // todo: add control method?
            DaemonWrap::Embedded(d) => Some(d.identity()),
        }
    }
}
