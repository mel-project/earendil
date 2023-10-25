use bincode::Options;
use bytes::Bytes;
use earendil_crypt::{Fingerprint, IdentityPublic, IdentitySecret};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    crypt::{box_decrypt, box_encrypt, OnionPublic, OnionSecret},
    reply_block::ReplyBlock,
};

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
/// Represents the actual end-to-end packet that is carried in the 8192-byte payloads. Either an application-level message, or a batch of reply blocks.
pub enum InnerPacket {
    Message(Message),
    ReplyBlocks(Vec<ReplyBlock>),
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
/// An inner packet message with corresponding UDP port-like source and destinaton docks
pub struct Message {
    source_dock: Dock,
    dest_dock: Dock,
    body: Bytes,
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
pub enum OpenError {
    #[error("outer packaging is bad")]
    OuterBad(bincode::Error),
    #[error("inner packaging is bad")]
    InnerBad(bincode::Error),
    #[error("decryption failed")]
    DecryptionFailed,
}

#[derive(Error, Debug)]
pub enum SealError {
    #[error("serialization of outer packaging failed")]
    OuterBad(bincode::Error),
    #[error("serialization of inner packaging failed")]
    InnerBad(bincode::Error),
    #[error("message is too big to fit in the payload")]
    MessageTooBig,
}

impl InnerPacket {
    /// From a raw payload, deduce the inner packet as well as the source fingerprint.
    pub fn open(raw: &[u8; 8192], my_osk: &OnionSecret) -> Result<(Self, Fingerprint), OpenError> {
        let coder = bincode::DefaultOptions::new().allow_trailing_bytes();
        let ctext: InnerPacketCiphertext =
            coder.deserialize(&raw[..]).map_err(OpenError::OuterBad)?;
        // decrypt
        let (box_ptext, box_epk) = box_decrypt(&ctext.box_ctext, my_osk)
            .ok()
            .ok_or(OpenError::DecryptionFailed)?;
        // check that the signature is correct
        if ctext
            .source_sign_pk
            .verify(box_epk.as_bytes(), &ctext.epk_sig)
            .is_err()
        {
            return Err(OpenError::DecryptionFailed);
        }
        // decode the plaintext
        let inner: InnerPacket = coder.deserialize(&box_ptext).map_err(OpenError::InnerBad)?;
        Ok((inner, ctext.source_sign_pk.fingerprint()))
    }

    /// Seals into a raw payload, given our signing SK and their onion PK
    pub fn seal(
        &self,
        my_isk: &IdentitySecret,
        their_opk: &OnionPublic,
    ) -> Result<[u8; 8192], SealError> {
        let coder = bincode::DefaultOptions::new().allow_trailing_bytes();

        // First, we serialize the InnerPacket
        let inner_ptext = coder.serialize(&self).map_err(SealError::InnerBad)?;

        // Then, we encrypt this serialized data
        let (box_ctext, box_esk) = box_encrypt(&inner_ptext, their_opk);

        // We sign the ephemeral public key
        let epk_sig = my_isk.sign(box_esk.public().as_bytes());

        // We prepare the InnerPacketCiphertext, which includes the source's signing public key, the signed ephemeral public key, and the ciphertext
        let ctext = InnerPacketCiphertext {
            source_sign_pk: my_isk.public(),
            epk_sig,
            box_ctext: Bytes::from(box_ctext),
        };

        // We serialize this ciphertext
        let packet = coder.serialize(&ctext).map_err(SealError::OuterBad)?;

        // We check if the packet is too big to fit in 8192 bytes
        if packet.len() > 8192 {
            return Err(SealError::MessageTooBig);
        }

        // We build our final byte array, filling with zeroes if the packet is smaller than 8192
        let mut result = [0u8; 8192];
        result[..packet.len()].copy_from_slice(&packet);

        Ok(result)
    }
}

impl Message {
    pub fn new(source_dock: Dock, dest_dock: Dock, body: Bytes) -> Self {
        Message {
            source_dock,
            dest_dock,
            body,
        }
    }

    pub fn get_source_dock(&self) -> &Dock {
        &self.source_dock
    }

    pub fn get_dest_dock(&self) -> &Dock {
        &self.dest_dock
    }

    pub fn get_body(&self) -> &Bytes {
        &self.body
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inner_packet_roundtrip() {
        // Step 1: Generate OnionSecret and IdentitySecret
        let onion_secret = OnionSecret::generate();
        let identity_secret = IdentitySecret::generate();

        // Step 2: Create an InnerPacket
        let inner_packet =
            InnerPacket::Message(Message::new(42u32, 200u32, Bytes::from("Hello, World!")));

        // Step 3: Encrypt the InnerPacket
        let encrypted_packet = inner_packet
            .seal(&identity_secret, &onion_secret.public())
            .expect("Can't encrypt packet");

        // Step 4: Decrypt the InnerPacket
        let (decrypted_packet, _) =
            InnerPacket::open(&encrypted_packet, &onion_secret).expect("Can't decrypt packet");

        // Step 5: Assert that the original and decrypted InnerPackets are equal
        assert_eq!(
            inner_packet, decrypted_packet,
            "Decrypted packet does not match the original one"
        );
    }
}
