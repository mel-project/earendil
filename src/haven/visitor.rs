use bytes::Bytes;
use earendil_crypt::RelayFingerprint;
use smol::channel::{Receiver, Sender};

use crate::{context::DaemonContext, socket::HavenEndpoint};

pub async fn visitor_loop(
    ctx: DaemonContext,
    send_downstream: Sender<Bytes>,
    recv_upstream: Receiver<Bytes>,
    rendezvous: RelayFingerprint,
    haven: HavenEndpoint,
) -> anyhow::Result<()> {
    todo!()
}
