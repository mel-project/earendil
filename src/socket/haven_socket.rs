use bytes::Bytes;
use clone_macro::clone;
use earendil_crypt::{AnonEndpoint, HavenIdentitySecret, RelayFingerprint};
use earendil_packet::crypt::OnionSecret;
use moka::sync::Cache;
use smol::{
    channel::{Receiver, Sender},
    Task, Timer,
};
use smol_timeout::TimeoutExt;
use smolscale::immortal::{Immortal, RespawnStrategy};
use std::time::Duration;

use crate::{
    context::DaemonContext,
    daemon::dht::dht_insert,
    global_rpc::{transport::GlobalRpcTransport, GlobalRpcClient},
    haven_util::{HavenLocator, RegisterHavenReq},
};

use super::{
    crypt_session::{CryptSession, HavenMsg},
    n2r_socket::N2rClientSocket,
    HavenEndpoint, HavenFingerprint, SocketSendError,
};

pub type Port = u16;

pub struct VisitorSocket {
    ctx: DaemonContext,
    n2r_socket: N2rClientSocket,
    identity_sk: HavenIdentitySecret,
    /// mapping between destination endpoints and encryption sessions
    crypt_sessions: Cache<HavenFingerprint, CryptSession>,
    /// buffer for decrypted incoming messages
    recv_incoming_decrypted: Receiver<(Bytes, HavenFingerprint)>,
    send_incoming_decrypted: Sender<(Bytes, HavenFingerprint)>,
    /// task that dispatches not-yet decrypted incoming packets to their right encrypters
    _recv_task: Immortal,
}

// HavenSocket with haven_info = None is a visitor socket; otherwise it's a haven
pub struct HavenSocket {
    ctx: DaemonContext,
    n2r_socket: N2rClientSocket,
    identity_sk: HavenIdentitySecret,
    port: Port,
    rendezvous: RelayFingerprint,
    _register_haven_task: Task<()>,
    /// mapping between destination endpoints and encryption sessions
    crypt_sessions: Cache<HavenFingerprint, CryptSession>,
    /// buffer for decrypted incoming messages
    recv_incoming_decrypted: Receiver<(Bytes, HavenEndpoint)>,
    send_incoming_decrypted: Sender<(Bytes, HavenEndpoint)>,
    /// task that dispatches not-yet decrypted incoming packets to their right encrypters
    _recv_task: Immortal,
}

impl HavenSocket {
    #[tracing::instrument(skip(ctx))]
    pub fn bind(
        ctx: DaemonContext,
        identity_sk: HavenIdentitySecret,
        port: Port,
        rendezvous: RelayFingerprint,
    ) -> anyhow::Result<HavenSocket> {
        let my_anon_ep = AnonEndpoint::new();
        let n2r_skt = N2rClientSocket::bind(ctx.clone(), my_anon_ep)?;

        let encrypters: Cache<HavenFingerprint, CryptSession> = Cache::builder()
            .max_capacity(100_000)
            .time_to_live(Duration::from_secs(60 * 30))
            .build();
        let (send_incoming_decrypted, recv_incoming_decrypted) = smol::channel::bounded(1000);
        let recv_task = Immortal::respawn(
            RespawnStrategy::Immediate,
            clone!(
                [n2r_skt, encrypters, send_incoming_decrypted, ctx],
                move || {
                    recv_task(
                        n2r_skt.clone(),
                        encrypters.clone(),
                        identity_sk,
                        Some(rendezvous),
                        send_incoming_decrypted.clone(),
                        ctx.clone(),
                    )
                }
            ),
        );
        // spawn a task that keeps telling our rendezvous relay node to remember us once in a while
        tracing::debug!("binding haven with rendezvous_point {}", rendezvous);
        let context = ctx.clone();
        let n2r_socket = n2r_skt.clone();
        let task = smolscale::spawn(async move {
            // generate a new onion keypair
            let onion_sk = OnionSecret::generate();
            let onion_pk = onion_sk.public();
            // register forwarding with the rendezvous relay node
            let gclient = GlobalRpcClient(GlobalRpcTransport::new(
                context.clone(),
                rendezvous,
                n2r_socket.clone(),
            ));
            let forward_req = RegisterHavenReq::new(my_anon_ep, identity_sk, port);

            loop {
                let n2r_skt = n2r_socket.clone();
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
                        dht_insert(
                            &context,
                            HavenLocator::new(identity_sk, onion_pk, rendezvous),
                            n2r_skt,
                        )
                        .timeout(Duration::from_secs(30))
                        .await;
                        Timer::after(Duration::from_secs(5)).await;
                    }
                }
            }
        });

        Ok(HavenSocket {
            ctx,
            n2r_socket: n2r_skt.clone(),
            _register_haven_task: Some(task),
            crypt_sessions: encrypters,
            recv_incoming_decrypted,
            send_incoming_decrypted,
            _recv_task: recv_task,
            identity_sk,
            port,
            rendezvous,
        })
    }

    #[tracing::instrument(skip(self))]
    pub async fn send_to(&self, body: Bytes, endpoint: VisitorEndpoint) -> anyhow::Result<()> {
        log::debug!("sending a message from haven");
        let enc = self
            .crypt_sessions
            .try_get_with(endpoint, || {
                CryptSession::new(
                    self.identity_sk,
                    endpoint,
                    self.rendezvous_point,
                    self.n2r_socket.clone(),
                    self.send_incoming_decrypted.clone(),
                    self.ctx.clone(),
                    None,
                )
            })
            .map_err(|e| SocketSendError::HavenEncryptionError(e.to_string()))?;
        if let Err(e) = enc.send_outgoing(body).await {
            self.crypt_sessions.remove(&endpoint);
            anyhow::bail!("haven encryption error {e}");
        } else {
            Ok(())
        }
    }

    pub async fn recv_from(&self) -> anyhow::Result<(Bytes, HavenEndpoint)> {
        Ok(self
            .recv_incoming_decrypted
            .recv()
            .await
            .expect("this must be infallible here, because the sending side is never dropped"))
    }

    pub fn local_endpoint(&self) -> HavenEndpoint {
        let n2r_endpoint = self.n2r_socket.local_endpoint();
        n2r_endpoint
    }
}

async fn recv_task(
    n2r_skt: N2rClientSocket,
    encrypters: Cache<HavenFingerprint, CryptSession>,
    isk: HavenIdentitySecret,
    rendezvous: Option<RelayFingerprint>,
    send_incoming_decrypted: Sender<(Bytes, HavenFingerprint)>,
    ctx: DaemonContext,
) -> anyhow::Result<()> {
    loop {
        let (n2r_msg, _rendezvous_ep) = n2r_skt.recv_from().await?;
        let (body, remote): (Bytes, HavenFingerprint) = stdcode::deserialize(&n2r_msg)?;
        let haven_msg: HavenMsg = stdcode::deserialize(&body)?;

        let encrypter = encrypters.get(&remote);
        match haven_msg.clone() {
            HavenMsg::ServerHs(_) => match encrypter {
                Some(enc) => enc.send_incoming(haven_msg).await?,
                None => anyhow::bail!("stray msg; dropping"),
            },
            HavenMsg::ClientHs(hs) => encrypters.insert(
                remote,
                CryptSession::new(
                    isk,
                    remote,
                    rendezvous,
                    n2r_skt.clone(),
                    send_incoming_decrypted.clone(),
                    ctx.clone(),
                    Some((hs, remote.fingerprint)),
                )?,
            ),
            HavenMsg::Regular { nonce: _, inner: _ } => match encrypter {
                Some(enc) => enc.send_incoming(haven_msg).await?,
                None => anyhow::bail!("stray msg; dropping"),
            },
        }
    }
}
