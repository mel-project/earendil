use bytes::Bytes;
use earendil_crypt::RelayFingerprint;
use smol::{
    channel::{Receiver, Sender},
    future::FutureExt as _,
};
use stdcode::StdcodeSerializeExt;

use crate::n2r_socket::{N2rClientSocket, RelayEndpoint};

use super::{
    vrh::{HavenMsg, V2rMessage},
    HavenEndpoint, HAVEN_FORWARD_DOCK,
};

pub async fn visitor_loop(
    send_downstream: Sender<Bytes>,
    recv_upstream: Receiver<Bytes>,
    rendezvous: RelayFingerprint,
    haven: HavenEndpoint,
    n2r_socket: N2rClientSocket,
) -> anyhow::Result<()> {
    let rendezvous = RelayEndpoint::new(rendezvous, HAVEN_FORWARD_DOCK);
    // upstream messages are wrapped in V2rMessage
    let up_loop = async {
        loop {
            let to_send = recv_upstream.recv().await?;
            n2r_socket
                .send_to(
                    V2rMessage {
                        dest_haven: haven,
                        payload: HavenMsg::Regular(to_send),
                    }
                    .stdcode()
                    .into(),
                    rendezvous,
                )
                .await?;
        }
    };
    // downstream messages are straight HavenMsgs
    let dn_loop = async {
        loop {
            let (msg, _) = n2r_socket.recv_from().await?;
            let msg: HavenMsg = stdcode::deserialize(&msg)?;
            match msg {
                HavenMsg::Regular(payload) => send_downstream.send(payload).await?,
                _ => anyhow::bail!("haven sent a non-regular message"),
            }
        }
    };
    up_loop.race(dn_loop).await
}
