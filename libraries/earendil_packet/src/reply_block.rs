use bytes::Bytes;
use earendil_crypt::{Fingerprint, IdentitySecret};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::{
    crypt::{stream_dencrypt, OnionPublic, OnionSecret},
    DecodeError, ForwardInstruction, InnerPacket, Message, PacketConstructError, RawHeader,
    RawPacket,
};

/// A reply block. Reply blocks are constructed by endpoints who wish other endpoints to talk to them via an anonymous address, and are single-use, consumed when used to construct a packet going to that anonymous address.
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub struct ReplyBlock {
    pub header: RawHeader,
    pub e2e_dest: OnionPublic,
    pub stream_key: [u8; 32],
    pub first_peeler: Fingerprint,
}

impl ReplyBlock {
    pub fn new(
        route: &[ForwardInstruction],
        first_peeler: Fingerprint,
        dest_opk: &OnionPublic,
        dest_is_relay: bool,
        my_anon_osk: OnionSecret,
        my_anon_isk: IdentitySecret,
    ) -> Result<(Self, (u64, ReplyDegarbler)), PacketConstructError> {
        let my_anon_opk = my_anon_osk.public();

        let rb_id: u64 = rand::random();
        let mut metadata = [0; 20];
        // metadata field for reply blocks: 8 bytes of a big-endian encoded unsigned integer, followed by 12 bytes of 0's
        metadata[0..8].copy_from_slice(&rb_id.to_be_bytes());

        let (raw_packet, shared_secs) = RawPacket::new(
            route,
            dest_opk,
            dest_is_relay,
            InnerPacket::Message(Message {
                source_dock: 0u32,
                dest_dock: 0u32,
                body: vec![Bytes::new()],
            }),
            &metadata,
            &my_anon_isk,
        )?;
        let header = raw_packet.header;
        let stream_key = rand::thread_rng().gen();

        let rb_degarbler = ReplyDegarbler {
            shared_secs,
            my_anon_osk,
            my_anon_isk,
            stream_key,
        };
        Ok((
            Self {
                header,
                e2e_dest: my_anon_opk,
                stream_key,
                first_peeler,
            },
            (rb_id, rb_degarbler),
        ))
    }
}

#[derive(Clone)]
pub struct ReplyDegarbler {
    shared_secs: Vec<[u8; 32]>,
    my_anon_osk: OnionSecret,
    my_anon_isk: IdentitySecret,
    stream_key: [u8; 32],
}

impl ReplyDegarbler {
    pub fn degarble(
        &self,
        raw: &mut [u8; 8192],
    ) -> Result<(InnerPacket, Fingerprint), DecodeError> {
        for shared_sec in &self.shared_secs {
            let body_key = blake3::keyed_hash(b"body____________________________", shared_sec);
            stream_dencrypt(body_key.as_bytes(), &[0; 12], raw);
        }
        stream_dencrypt(&self.stream_key, &[0; 12], &mut raw[..]);
        InnerPacket::decode(raw)
    }

    pub fn my_anon_osk(&self) -> OnionSecret {
        self.my_anon_osk.clone()
    }

    pub fn my_anon_isk(&self) -> IdentitySecret {
        self.my_anon_isk
    }
}
