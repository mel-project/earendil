use std::{fmt::Display, str::FromStr};

use earendil_crypt::Fingerprint;
use serde::{Deserialize, Serialize};

/// A unique identifier of an endpoint that can be the source or destination of packets.
#[derive(Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Clone, Copy, Debug)]
pub enum Address {
    Clear(Fingerprint),
    Anon(AnonAddress),
}

impl FromStr for Address {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(fp) = Fingerprint::from_str(s) {
            Ok(Self::Clear(fp))
        } else {
            Ok(Self::Anon(AnonAddress::from_str(s)?))
        }
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clear(fp) => fp.fmt(f),
            Self::Anon(anon) => anon.fmt(f),
        }
    }
}

/// A temporary address, uniquely identifying an endpoint that can only be reached by reply block.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Ord, Eq, Hash, Serialize, Deserialize)]
pub struct AnonAddress([u8; 20]);

impl Display for AnonAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let b64 = bs58::encode(self.0).into_string();
        write!(f, "anon-{}", b64)
    }
}

impl FromStr for AnonAddress {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(stripped) = s.strip_prefix("anon-") {
            let bytes = bs58::decode(stripped).into_vec()?;
            if bytes.len() == 20 {
                let mut arr = [0u8; 20];
                arr.copy_from_slice(&bytes);
                Ok(Self(arr))
            } else {
                Err(anyhow::anyhow!("Invalid fingerprint length"))
            }
        } else {
            Err(anyhow::anyhow!("String does not start with 'anon-'"))
        }
    }
}
