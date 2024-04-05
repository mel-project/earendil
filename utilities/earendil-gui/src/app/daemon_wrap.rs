use std::{net::SocketAddr, sync::Arc};

use earendil::{control_protocol::ControlClient, daemon::Daemon};
use earendil_crypt::RelayFingerprint;
use either::Either;

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

    pub fn identity(&self) -> Either<u64, RelayFingerprint> {
        match self {
            DaemonWrap::Remote(_) => todo!(), // todo: add control method?
            DaemonWrap::Embedded(d) => {
                if let Some(sk) = d.identity() {
                    Either::Right(sk.public().fingerprint())
                } else {
                    Either::Left(d.client_id())
                }
            }
        }
    }

    pub fn is_dead(&self) -> bool {
        match self {
            DaemonWrap::Remote(_) => todo!(),
            DaemonWrap::Embedded(daemon) => daemon.is_dead(),
        }
    }
}
