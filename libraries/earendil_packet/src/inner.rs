use arrayref::array_ref;
use bincode::Options;
use bytes::Bytes;
use earendil_crypt::{Fingerprint, IdentityPublic, IdentitySecret};
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
    pub source_dock: Dock,
    pub dest_dock: Dock,
    pub body: Vec<Bytes>,
}

pub type Dock = u32;

#[derive(Serialize, Deserialize)]
struct InnerPacketCiphertext {
    source_sign_pk: IdentityPublic,
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
}

#[derive(Error, Debug)]
pub enum EncodeError {
    #[error("serialization of outer packaging failed")]
    BadPackaging(bincode::Error),

    #[error("message is too big to fit in the payload")]
    MessageTooBig,
}

impl InnerPacket {
    /// From a raw payload, deduce the inner packet as well as the source fingerprint.
    pub fn decode(raw: &[u8; 8192]) -> Result<(Self, Fingerprint), DecodeError> {
        let src_fp = Fingerprint::from_bytes(array_ref![raw, 0, 20]);
        let coder = bincode::DefaultOptions::new().allow_trailing_bytes();
        let msg: Self = coder
            .deserialize(&raw[20..])
            .map_err(DecodeError::BadPackaging)?;
        Ok((msg, src_fp))
    }

    /// Encodes into a raw payload, given our signing SK and their onion PK
    pub fn encode(&self, my_isk: &IdentitySecret) -> Result<[u8; 8192], EncodeError> {
        let mut toret = [0u8; 8192];
        toret[..20].copy_from_slice(my_isk.public().fingerprint().as_bytes());
        let coder = bincode::DefaultOptions::new().allow_trailing_bytes();
        coder
            .serialize_into(&mut toret[20..], &self)
            .map_err(EncodeError::BadPackaging)?;
        Ok(toret)
    }
}

impl Message {
    pub fn new(source_dock: Dock, dest_dock: Dock, body: Vec<Bytes>) -> Self {
        Message {
            source_dock,
            dest_dock,
            body,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_inner_packet_roundtrip() {
        // Step 1: Generate OnionSecret and IdentitySecret

        let identity_secret = IdentitySecret::generate();

        // Step 2: Create an InnerPacket
        let inner_packet = InnerPacket::Message(Message::new(
            42u32,
            200u32,
            vec![Bytes::from("Hello, World!")],
        ));

        // Step 3: Encrypt the InnerPacket
        let encrypted_packet = inner_packet
            .encode(&identity_secret)
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
