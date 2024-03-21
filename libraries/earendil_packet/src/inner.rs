use arrayref::array_ref;
use bincode::Options;
use bytes::Bytes;
use earendil_crypt::{AnonEndpoint, RelayFingerprint, RelayIdentityPublic, RemoteId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::reply_block::ReplyBlock;

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
/// Represents the actual end-to-end packet that is carried in the 8192-byte payloads. Either an application-level message, or a batch of reply blocks.
pub enum InnerPacket {
    /// Normal messages
    Message(Message),
    /// Reply blocks, used to construct relay->anon messages
    ReplyBlocks(Vec<ReplyBlock>),
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
/// An inner packet message with corresponding UDP port-like source and destinaton docks
pub struct Message {
    pub relay_dock: Dock,
    pub body: Bytes,
}

pub type Dock = u32;

#[derive(Serialize, Deserialize)]
struct InnerPacketCiphertext {
    source_sign_pk: RelayIdentityPublic,
    epk_sig: Bytes,
    box_ctext: Bytes,
}

/// Things that can go wrong when parsing an InnerPacket
#[derive(Error, Debug)]
pub enum DecodeError {
    #[error("outer packaging is bad")]
    BadPackaging(bincode::Error),

    #[error("decryption failed")]
    DecryptionFailed,

    #[error("bad metadata")]
    BadMetadata,
}

#[derive(Error, Debug)]
pub enum EncodeError {
    #[error("serialization of outer packaging failed")]
    BadPackaging(bincode::Error),

    #[error("message is too big to fit in the payload")]
    MessageTooBig,
}

const SOURCE_LENGTH: usize = 33;

impl InnerPacket {
    /// From a raw payload, deduce the inner packet as well as the source id.
    pub fn decode(raw: &[u8; 8192]) -> Result<(Self, RemoteId), DecodeError> {
        let src_node_id = match array_ref![raw, 0, 1] {
            [0u8] => {
                let src_fp = RelayFingerprint::from_bytes(array_ref![raw, 1, 32]);
                RemoteId::Relay(src_fp)
            }
            [1u8] => {
                let anon_dest = AnonEndpoint(*array_ref![raw, 1, 16]);
                RemoteId::Anon(anon_dest)
            }
            _ => return Err(DecodeError::BadMetadata),
        };
        let coder = bincode::DefaultOptions::new().allow_trailing_bytes();
        let msg: Self = coder
            .deserialize(&raw[SOURCE_LENGTH..])
            .map_err(DecodeError::BadPackaging)?;
        Ok((msg, src_node_id))
    }

    /// Encodes into a raw payload, given our node id
    pub fn encode(&self, my_id: &RemoteId) -> Result<[u8; 8192], EncodeError> {
        let mut toret = [0u8; 8192];

        match my_id {
            RemoteId::Relay(fingerprint) => {
                toret[0] = 0;
                toret[1..SOURCE_LENGTH].copy_from_slice(fingerprint.as_bytes());
            }
            RemoteId::Anon(anon_dest) => {
                toret[0] = 1;
                toret[1..17].copy_from_slice(&anon_dest.0);
            }
        }
        let coder = bincode::DefaultOptions::new().allow_trailing_bytes();
        coder
            .serialize_into(&mut toret[SOURCE_LENGTH..], &self)
            .map_err(EncodeError::BadPackaging)?;
        Ok(toret)
    }
}

impl Message {
    pub fn new(relay_dock: Dock, body: Bytes) -> Self {
        Message { relay_dock, body }
    }
}

#[cfg(test)]
mod tests {

    use earendil_crypt::RelayIdentitySecret;

    use super::*;

    #[test]
    fn test_inner_packet_roundtrip() {
        // Step 1: Generate OnionSecret and IdentitySecret

        let identity_secret = RelayIdentitySecret::generate();

        // Step 2: Create an InnerPacket
        let inner_packet = InnerPacket::Message(Message::new(200u32, Bytes::from("Hello, World!")));

        // Step 3: Encode the InnerPacket
        let encrypted_packet = inner_packet
            .encode(&RemoteId::Relay(identity_secret.public().fingerprint()))
            .expect("Can't encrypt packet");

        // Step 4: Decrypt the InnerPacket
        let (decrypted_packet, _) =
            InnerPacket::decode(&encrypted_packet).expect("Can't decrypt packet");

        // Step 5: Assert that the original and decrypted InnerPackets are equal
        assert_eq!(
            inner_packet, decrypted_packet,
            "Decrypted packet does not match the original one"
        );
    }
}
