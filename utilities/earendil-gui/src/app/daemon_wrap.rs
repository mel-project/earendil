use std::net::SocketAddr;

use earendil::{control_protocol::ControlClient, daemon::Daemon};

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
}
