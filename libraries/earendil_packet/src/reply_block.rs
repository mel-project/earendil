use bytes::Bytes;
use earendil_crypt::{AnonEndpoint, ClientId, RelayFingerprint, RemoteId};
use rand::Rng;

use serde::{Deserialize, Serialize};

use crate::{
    crypt::{stream_dencrypt, DhPublic},
    InnerPacket, Message, PacketConstructError, PeelInstruction, PrivacyConfig, RawBody, RawHeader,
    RawPacket,
};

/// A single-use reply block. Surbs are constructed by endpoints who wish other endpoints to talk to them via an anonymous address, and are single-use, consumed when used to construct a packet going to that anonymous address.
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub struct Surb {
    pub header: RawHeader,
    pub stream_key: [u8; 32],
    pub first_peeler: RelayFingerprint,
}

impl Surb {
    pub fn new(
        route: &[PeelInstruction],
        first_peeler: RelayFingerprint,
        dest_opk: &DhPublic,
        my_client_id: ClientId,
        my_anon_id: AnonEndpoint,
        privacy_cfg: PrivacyConfig,
    ) -> Result<(Self, ReplyDegarbler), PacketConstructError> {
        let surb_id: u64 = rand::random();
        // println!("made rb with rb_id = {rb_id}");
        let mut metadata = [0; 32];
        // metadata field for reply blocks: 8 bytes of a big-endian encoded unsigned integer, followed by 12 bytes of 0's
        metadata[0..8].copy_from_slice(&my_client_id.to_be_bytes());
        metadata[8..16].copy_from_slice(&surb_id.to_be_bytes());

        let (raw_packet, shared_secs) = RawPacket::new(
            route,
            dest_opk,
            true,
            InnerPacket::Message(Message {
                relay_dock: 0u32,
                body: Bytes::new(),
                remaining_surbs: 0,
            }),
            &metadata,
            RemoteId::Anon(my_anon_id),
            privacy_cfg,
        )?;
        let header = raw_packet.header;
        let stream_key = rand::thread_rng().gen();

        let degarbler = ReplyDegarbler {
            surb_id,
            shared_secs,
            my_anon_id,
            stream_key,
        };
        Ok((
            Self {
                header,
                stream_key,
                first_peeler,
            },
            degarbler,
        ))
    }
}

#[derive(Clone)]
pub struct ReplyDegarbler {
    surb_id: u64,
    shared_secs: Vec<[u8; 32]>,
    my_anon_id: AnonEndpoint,
    stream_key: [u8; 32],
}

impl ReplyDegarbler {
    pub fn surb_id(&self) -> u64 {
        self.surb_id
    }
    pub fn degarble(&self, raw: &mut RawBody) -> anyhow::Result<(InnerPacket, RelayFingerprint)> {
        for shared_sec in &self.shared_secs {
            let body_key = blake3::keyed_hash(b"body____________________________", shared_sec);
            stream_dencrypt(body_key.as_bytes(), &[0; 12], raw);
        }
        stream_dencrypt(&self.stream_key, &[0; 12], &mut raw[..]);
        let (inner, src) = InnerPacket::decode(raw)?;

        match src {
            RemoteId::Relay(fp) => Ok((inner, fp)),
            RemoteId::Anon(_) => anyhow::bail!("clients can't receive packets from clients"),
        }
    }

    pub fn my_anon_id(&self) -> AnonEndpoint {
        self.my_anon_id
    }
}
