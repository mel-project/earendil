use serde::{Deserialize, Serialize};

use crate::{crypt::OnionPublic, ForwardInstruction, RawHeader, RawPacket};

/// A reply block. Reply blocks are constructed by endpoints who wish other endpoints to talk to them via an anonymous address, and are single-use, consumed when used to construct a packet going to that anonymous address.
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub struct ReplyBlock {
    pub header: RawHeader,
    pub e2e_dest: OnionPublic,
}

impl ReplyBlock {
    pub fn new(
        my_onion_public: OnionPublic,
        route: &[ForwardInstruction],
    ) -> anyhow::Result<(Self, (u64, RbDegarbler))> {
        let dummy_payload = [0; 8192];
        let rb_id: u64 = rand::random();
        let mut metadata = [0; 20];
        // metadata field for reply blocks: 8 bytes of a big-endian encoded unsigned integer, followed by 12 bytes of 0's
        metadata[0..8].copy_from_slice(&rb_id.to_be_bytes());
        let raw_packet = RawPacket::new(route, &my_onion_public, &dummy_payload, &metadata)?;
        let header = raw_packet.header;

        // TODO: construct RbDegarbler from raw_packet.onion_body
        let rb_degarbler = RbDegarbler {};
        Ok((
            Self {
                header,
                e2e_dest: my_onion_public,
            },
            (rb_id, rb_degarbler),
        ))
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub struct RbDegarbler {}
