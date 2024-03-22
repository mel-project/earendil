use crate::context::DaemonContext;
use crate::haven_util::RegisterHavenReq;
use crate::socket::HavenEndpoint;
use crate::socket::RelayEndpoint;
use bytes::Bytes;
use earendil_crypt::HavenIdentityPublic;
use earendil_crypt::HavenIdentitySecret;
use earendil_packet::crypt::AeadKey;
use earendil_packet::crypt::OnionPublic;
use serde::Deserialize;
use serde::Serialize;
use smol::Task;

#[derive(Clone, Serialize, Deserialize)]
pub enum HavenMsg {
    ClientHs(ClientHandshake),
    ServerHs(ServerHandshake),
    Regular { nonce: u64, inner: Bytes },
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ServerHandshake {
    id_pk: HavenIdentityPublic,
    eph_pk: OnionPublic,
    sig: Bytes,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ClientHandshake(OnionPublic);

pub struct HavenListener {
    _register_task: Task<()>,
    // channel for putting all incoming ClientHandshakes
    incoming_handshakes: smol::channel::Receiver<ClientHandshake>,
    // table mapping IDs to sending-ends of channels, so that we can direct incoming packets to the right HavenConnection
    // basically a demultiplexer similar to the demultiplexer that redirects incoming N2R packets to the right queue
}

impl HavenListener {
    pub async fn bind(
        ctx: DaemonContext,
        rendezvous: RelayEndpoint,
        identity_sk: HavenIdentitySecret,
    ) -> anyhow::Result<Self> {
        // contact the rendezvous
        // upload our haven info into the DHT

        let _register_task = smolscale::spawn(async move { loop {} });
        // construct HavenListener with the right background task running as well
        todo!()
    }
    pub async fn accept(&self) -> anyhow::Result<HavenConnection> {
        // communicate with the internal task, probably by reading from a channel
        let handshake = self.incoming_handshakes.recv().await?;

        todo!()
    }
}

pub struct HavenConnection {
    // encryption state for this connection
    enc_key: AeadKey,
    dec_key: AeadKey,
    // some way of sending packets to the other side (e.g. the sending end of a channel, or a boxed closure)
    // some way of receiving packets from the other side (e.g. the receiving end of a channel, or a boxed closure)
    // these channels are provided by whoever constructs this connection:
    // - for connect(), they should connect to tasks that shuffle packets to/from the rendezvous
    // - for the haven side, it's a bit more complex. the haven listener should spawn some task that manages a table of channels, similar to how we currently manage a table of encrypters. this task should go through all incoming packets, finishing encryption handshakes, and constructing HavenConnections by filling in its fields with the correct encryption state as well as the right packet-sending and packet-receiving functionality.
}

impl HavenConnection {
    pub async fn connect(haven: HavenEndpoint) -> anyhow::Result<Self> {
        // lookup the haven info using the dht
        let rendezvous_locator = dht_get(&ctx, haven_endpoint.fingerprint, self.n2r_skt.clone())
            .timeout(Duration::from_secs(30))
            .await
            .context(format!("DHT failed for {}", remote.fingerprint))?
            .context(format!("DHT returned None for {}", remote.fingerprint))?;
        let rendezvous_ep =
            RelayEndpoint::new(rendezvous_locator.rendezvous_point, HAVEN_FORWARD_DOCK);
        // do the handshake to the other side over N2R
        let my_osk = OnionSecret::generate();
        let handshake = ClientHandshake(my_osk.public());
        self.n2r_skt.send(stdcode::serialize(&handshake)).await?;

        let server_hs: ServerHandshake = stdcode::deserialize(&n2r_skt.recv().await?)?;
        server_hs
            .id_pk
            .verify(server_hs.to_sign().as_bytes(), &server_hs.sig)?;
        if hs.id_pk.fingerprint() != fp {
            anyhow::bail!("spoofed source fingerprint for server handshake!")
        }

        // construct the connection
        Ok(HavenConnection {
            enc_key: todo!(),
            dec_key: todo!(),
        })
    }

    pub async fn send(&self, bts: &[u8]) -> anyhow::Result<()> {
        todo!()
    }

    pub async fn recv(&self) -> anyhow::Result<Bytes> {
        todo!()
    }
}
