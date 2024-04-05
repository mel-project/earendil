use bytes::Bytes;

use earendil_crypt::{AnonEndpoint, HavenIdentitySecret, RelayFingerprint};
use earendil_packet::crypt::{AeadKey, DhSecret};
use smol::{
    channel::{Receiver, Sender},
    future::FutureExt as _,
    Timer,
};
use smol_timeout::TimeoutExt;
use std::{collections::HashMap, sync::atomic::AtomicU64, time::Duration};
use stdcode::StdcodeSerializeExt;

use crate::{
    context::DaemonContext,
    dht::dht_insert,
    global_rpc::{transport::GlobalRpcTransport, GlobalRpcClient},
    haven::vrh::HavenHandshake,
    n2r_socket::{N2rClientSocket, RelayEndpoint},
};

use super::{
    vrh::{H2rMessage, HavenMsg, R2hMessage},
    HavenLocator, HavenPacketConn, RegisterHavenReq, HAVEN_DN, HAVEN_FORWARD_DOCK, HAVEN_UP,
};

pub async fn listen_loop(
    ctx: DaemonContext,
    identity: HavenIdentitySecret,
    port: u16,
    rendezvous: RelayFingerprint,
    send_accepted: Sender<HavenPacketConn>,
) -> anyhow::Result<()> {
    let anon_ep = AnonEndpoint::random();
    let n2r_socket = N2rClientSocket::bind(ctx.clone(), anon_ep)?;
    loop {
        // register ourselves with rendezvous & upload info to DHT in a loop
        let register_loop = register_haven(
            &ctx,
            identity,
            port,
            rendezvous,
            n2r_socket.local_endpoint(),
        );
        // start loop that demultiplexes incoming messages
        let demultiplex_loop = haven_demultiplex(
            identity,
            n2r_socket.clone(),
            rendezvous,
            send_accepted.clone(),
        );
        if let Err(err) = register_loop.race(demultiplex_loop).await {
            tracing::warn!(err = debug(err), "restarting listen");
            smol::Timer::after(Duration::from_secs(1)).await;
        }
    }
}

async fn register_haven(
    ctx: &DaemonContext,
    identity: HavenIdentitySecret,
    port: u16,
    rendezvous: RelayFingerprint,
    anon_endpoint: AnonEndpoint,
) -> anyhow::Result<()> {
    let esk = DhSecret::generate();
    let epk = esk.public();
    let forward_req = RegisterHavenReq::new(anon_endpoint, identity, port);
    let gclient = GlobalRpcClient(GlobalRpcTransport::new(
        ctx.clone(),
        rendezvous,
        N2rClientSocket::bind(ctx.clone(), AnonEndpoint::random())?,
    ));
    loop {
        let dht_socket = N2rClientSocket::bind(ctx.clone(), AnonEndpoint::random())?;
        match gclient
            .alloc_forward(forward_req.clone())
            .timeout(Duration::from_secs(10))
            .await
        {
            Some(Err(e)) => {
                tracing::debug!(
                    "registering haven rendezvous {} failed: {:?}",
                    rendezvous,
                    e
                );
                Timer::after(Duration::from_secs(3)).await;
                continue;
            }
            None => {
                tracing::debug!("registering haven rendezvous relay timed out");
                Timer::after(Duration::from_secs(3)).await;
            }
            _ => {
                tracing::debug!("registering haven {}", identity.public().fingerprint());
                dht_insert(
                    ctx,
                    HavenLocator::new(identity, epk, rendezvous),
                    &dht_socket,
                )
                .timeout(Duration::from_secs(30))
                .await;
                Timer::after(Duration::from_secs(5)).await;
            }
        }
    }
}

#[tracing::instrument(skip_all, fields(identity=display(identity.public().fingerprint())))]
async fn haven_demultiplex(
    identity: HavenIdentitySecret,
    n2r_socket: N2rClientSocket,
    rendezvous: RelayFingerprint,
    send_accepted: Sender<HavenPacketConn>,
) -> anyhow::Result<()> {
    let resupply_loop = async {
        loop {
            smol::Timer::after(Duration::from_secs(10)).await;
            tracing::trace!("resupplying reply blocks for the rendezvous ");
            n2r_socket.supply_reply_blocks(rendezvous).await?;
        }
    };

    resupply_loop
        .race(async {
            let mut conn_queues: HashMap<AnonEndpoint, Sender<Bytes>> = HashMap::new();
            loop {
                // *occasionally* cleanup the conn_queue. the probability given here makes this asymptotically constant time.
                if rand::random::<f64>() < 1.0 / (conn_queues.len() as f64) {
                    // eliminate all queues where the other side is gone
                    conn_queues.retain(|_, q| q.receiver_count() > 0)
                }

                let (msg, _) = n2r_socket.recv_from().await?;
                let msg_len = msg.len();
                let msg: Result<R2hMessage, _> = stdcode::deserialize(&msg);
                match msg {
                    Ok(R2hMessage {
                        src_visitor,
                        payload: HavenMsg::Regular(normal),
                    }) => {
                        let queue = conn_queues.get(&src_visitor);
                        if let Some(queue) = queue {
                            let _ = queue.try_send(normal);
                        } else {
                            tracing::warn!(
                                src_visitor = debug(src_visitor),
                                "r2h to unknown connection"
                            )
                        }
                    }
                    Ok(R2hMessage {
                        src_visitor,
                        payload: HavenMsg::VisitorHs(handshake),
                    }) => {
                        let eph_sk = DhSecret::generate();
                        let shared_sec = eph_sk.shared_secret(&handshake.0);
                        let up_key = AeadKey::from_bytes(
                            blake3::keyed_hash(blake3::hash(HAVEN_UP).as_bytes(), &shared_sec)
                                .as_bytes(),
                        );
                        let down_key = AeadKey::from_bytes(
                            blake3::keyed_hash(blake3::hash(HAVEN_DN).as_bytes(), &shared_sec)
                                .as_bytes(),
                        );
                        let (send_upstream, recv_upstream) = smol::channel::bounded(1000);
                        let (send_downstream, recv_downstream) = smol::channel::bounded(1000);
                        let conn = HavenPacketConn {
                            enc_key: down_key,
                            enc_nonce: AtomicU64::new(0),
                            dec_key: up_key,

                            send_upstream,
                            recv_downstream,
                            _task: smolscale::spawn(per_conn_loop(
                                recv_upstream,
                                src_visitor,
                                n2r_socket.clone(),
                                rendezvous,
                            )),
                        };
                        conn_queues.insert(src_visitor, send_downstream);

                        // Finish the handshake
                        let response = H2rMessage {
                            dest_visitor: src_visitor,
                            payload: HavenMsg::HavenHs(HavenHandshake {
                                id_pk: identity.public(),
                                eph_pk: eph_sk.public(),
                                sig: identity.sign(eph_sk.public().as_bytes()),
                            }),
                        };
                        n2r_socket
                            .send_to(
                                response.stdcode().into(),
                                RelayEndpoint::new(rendezvous, HAVEN_FORWARD_DOCK),
                            )
                            .await?;

                        send_accepted.send(conn).await?;
                    }
                    Ok(R2hMessage {
                        src_visitor,
                        payload: HavenMsg::HavenHs(_),
                    }) => {
                        tracing::warn!(
                            src_visitor = debug(src_visitor),
                            "invalid HavenHs at haven side"
                        )
                    }
                    Err(err) => {
                        tracing::warn!(err = debug(err), msg_len, "invalid R2H message")
                    }
                }
            }
        })
        .await
}

async fn per_conn_loop(
    recv_upstream: Receiver<Bytes>,
    dest_visitor: AnonEndpoint,
    n2r_socket: N2rClientSocket,
    rendezvous: RelayFingerprint,
) -> anyhow::Result<()> {
    loop {
        let to_send = recv_upstream.recv().await?;
        n2r_socket
            .send_to(
                H2rMessage {
                    dest_visitor,
                    payload: HavenMsg::Regular(to_send),
                }
                .stdcode()
                .into(),
                RelayEndpoint::new(rendezvous, HAVEN_FORWARD_DOCK),
            )
            .await?;
    }
}
