use earendil_crypt::Fingerprint;
use serde::{Deserialize, Serialize};

use crate::{
    crypt::{stream_dencrypt, OnionPublic, OnionSecret},
    ForwardInstruction, InnerPacket, OpenError, RawHeader, RawPacket,
};

/// A reply block. Reply blocks are constructed by endpoints who wish other endpoints to talk to them via an anonymous address, and are single-use, consumed when used to construct a packet going to that anonymous address.
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub struct ReplyBlock {
    pub header: RawHeader,
    pub e2e_dest: OnionPublic,
    // encrypted symmetric key
}

impl ReplyBlock {
    pub fn new(route: &[ForwardInstruction]) -> anyhow::Result<(Self, (u64, RbDegarbler))> {
        let my_onion_secret = OnionSecret::generate();
        let my_onion_public = my_onion_secret.public();

        let dummy_payload = [0; 8192];
        let rb_id: u64 = rand::random();
        let mut metadata = [0; 20];
        // metadata field for reply blocks: 8 bytes of a big-endian encoded unsigned integer, followed by 12 bytes of 0's
        metadata[0..8].copy_from_slice(&rb_id.to_be_bytes());

        let (raw_packet, shared_secs) =
            RawPacket::new(route, &my_onion_public, &dummy_payload, &metadata)?;
        let header = raw_packet.header;

        let rb_degarbler = RbDegarbler {
            shared_secs,
            my_onion_secret,
        };
        Ok((
            Self {
                header,
                e2e_dest: my_onion_public,
            },
            (rb_id, rb_degarbler),
        ))
    }

    /// creates a batch of reply blocks that fits into 1 earendil packet
    pub fn create_batch() -> InnerPacket {
        todo!()
    }
}

#[derive(Clone)]
pub struct RbDegarbler {
    shared_secs: Vec<[u8; 32]>,
    pub my_onion_secret: OnionSecret,
}

impl RbDegarbler {
    pub fn degarble(&self, raw: [u8; 8192]) -> Result<(InnerPacket, Fingerprint), OpenError> {
        let mut raw = raw;
        for shared_sec in &self.shared_secs {
            let body_key = blake3::keyed_hash(b"body____________________________", shared_sec);
            stream_dencrypt(body_key.as_bytes(), &[0; 12], &mut raw);
        }
        InnerPacket::open(&raw, &self.my_onion_secret)
    }
}
