use bincode::Options;
use bytes::Bytes;
use earendil_crypt::IdentityPublic;
use serde::{Deserialize, Serialize};

use crate::{Address, AnonAddress, RawHeader};

pub struct Source;

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
/// Represents the actual end-to-end packet that is carried in the 8192-byte payloads. Either an application-level message, or a batch of reply blocks.
pub enum InnerPacket {
    Message(Message),
    ReplyBlocks(Vec<ReplyBlock>),
}

struct InnerPacketCiphertext {
    source_signing_key: IdentityPublic,
}

impl InnerPacket {
    /// Converts from the raw payload.
    pub fn from_raw(raw: &[u8; 8192]) -> Result<Self, bincode::Error> {
        bincode::DefaultOptions::new()
            .allow_trailing_bytes()
            .deserialize(&raw[..])
    }

    /// Converts to the raw format
    pub fn as_raw(&self) -> Result<[u8; 8192], bincode::Error> {
        let mut buff = [0; 8192];
        bincode::DefaultOptions::new()
            .allow_trailing_bytes()
            .serialize_into(buff.as_mut_slice(), self)?;
        Ok(buff)
    }
}

#[derive(Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Clone, Debug)]
/// An application message.
pub struct Message {
    pub source: Address,
    pub body: Bytes,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
/// A reply block. Reply blocks are constructed by endpoints who wish other endpoints to talk to them via an anonymous address, and are single-use, consumed when used to construct a packet going to that anonymous address.
pub struct ReplyBlock {
    pub anon_source: AnonAddress,
    pub header: RawHeader,
    pub random_key: [u8; 32],
}
