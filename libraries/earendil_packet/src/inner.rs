

use bincode::Options;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::{Address, Fingerprint, RawHeader};

pub struct Source;

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub enum InnerPacket {
    Message(Message),
    ReplyBlocks(Vec<ReplyBlock>),
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

#[derive(Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Clone)]
pub struct Message {
    pub source: Address,
    pub body: Bytes,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct ReplyBlock {
    pub anon_source: u128,
    pub first_return_hop: Fingerprint,
    pub header: RawHeader,
    pub random_key: [u8; 32],
}
