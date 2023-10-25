use bytes::Bytes;
use earendil_crypt::{Fingerprint, IdentitySecret};
use serde::{Deserialize, Serialize};

use crate::{
    crypt::{stream_dencrypt, OnionPublic, OnionSecret},
    ForwardInstruction, InnerPacket, Message, OpenError, PacketConstructError, RawHeader,
    RawPacket,
};

/// A reply block. Reply blocks are constructed by endpoints who wish other endpoints to talk to them via an anonymous address, and are single-use, consumed when used to construct a packet going to that anonymous address.
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub struct ReplyBlock {
    pub header: RawHeader,
    pub e2e_dest: OnionPublic,
    // encrypted symmetric key
}

impl ReplyBlock {
    pub fn new(
        route: &[ForwardInstruction],
        my_opk: &OnionPublic,
        my_anon_osk: OnionSecret,
    ) -> Result<(Self, (u64, ReplyDegarbler)), PacketConstructError> {
        let my_anon_opk = my_anon_osk.public();

        let rb_id: u64 = rand::random();
        let mut metadata = [0; 20];
        // metadata field for reply blocks: 8 bytes of a big-endian encoded unsigned integer, followed by 12 bytes of 0's
        metadata[0..8].copy_from_slice(&rb_id.to_be_bytes());

        let (raw_packet, shared_secs) = RawPacket::new(
            route,
            my_opk,
            InnerPacket::Message(Message::new(0u32, 0u32, Bytes::new())),
            &metadata,
            &IdentitySecret::generate(),
        )?;
        let header = raw_packet.header;

        let rb_degarbler = ReplyDegarbler {
            shared_secs,
            my_anon_osk,
        };
        Ok((
            Self {
                header,
                e2e_dest: my_anon_opk,
            },
            (rb_id, rb_degarbler),
        ))
    }
}

#[derive(Clone)]
pub struct ReplyDegarbler {
    shared_secs: Vec<[u8; 32]>,
    my_anon_osk: OnionSecret,
}

impl ReplyDegarbler {
    pub fn degarble(&self, raw: &mut [u8; 8192]) -> Result<(InnerPacket, Fingerprint), OpenError> {
        for shared_sec in &self.shared_secs {
            let body_key = blake3::keyed_hash(b"body____________________________", shared_sec);
            stream_dencrypt(body_key.as_bytes(), &[0; 12], raw);
        }
        InnerPacket::open(raw, &self.my_anon_osk)
    }

    pub fn my_anon_osk(&self) -> &OnionSecret {
        &self.my_anon_osk
    }
}
