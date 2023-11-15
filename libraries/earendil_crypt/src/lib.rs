use std::{fmt::Display, str::FromStr};

use anyhow::Context;
use arrayref::array_ref;
use base32::Alphabet;
use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The public half of an "identity" on the network.
///
/// Underlying representation is a Ed25519 public key.
#[derive(Serialize, Debug, Deserialize, Clone, Copy, PartialEq, PartialOrd, Ord, Eq)]
pub struct IdentityPublic([u8; 32]);

impl TryFrom<Vec<u8>> for IdentityPublic {
    type Error = Vec<u8>;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl AsRef<[u8]> for IdentityPublic {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Error, Debug, Deserialize, Serialize)]
pub enum VerifyError {
    #[error("The signature is corrupt")]
    SignatureCorrupt,

    #[error("The signature mismatches")]
    SignatureMismatch,
}

impl IdentityPublic {
    /// Verifies a message supposedly signed by this key.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), VerifyError> {
        let pk = ed25519_compact::PublicKey::from_slice(&self.0)
            .map_err(|_| VerifyError::SignatureCorrupt)?;

        let sig = ed25519_compact::Signature::from_slice(sig)
            .map_err(|_| VerifyError::SignatureCorrupt)?;

        pk.verify(msg, &sig)
            .map_err(|_| VerifyError::SignatureMismatch)
    }

    /// The hash-based fingerprint of this identity.
    pub fn fingerprint(&self) -> Fingerprint {
        let hash = blake3::keyed_hash(b"fingerprint_____________________", &self.0);
        Fingerprint::from_bytes(array_ref![hash.as_bytes(), 0, 20])
    }
}

/// The secret half of an "identity" on the network.
///
/// Underlying representation is a Ed25519 "seed".
#[derive(Serialize, Deserialize, Clone, PartialEq, PartialOrd, Ord, Eq)]
pub struct IdentitySecret([u8; 32]);

impl FromStr for IdentitySecret {
    type Err = base64::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded = general_purpose::STANDARD.decode(s)?;
        if decoded.len() == 32 {
            let mut array = [0u8; 32];
            array.copy_from_slice(&decoded);
            Ok(IdentitySecret(array))
        } else {
            Err(base64::DecodeError::InvalidLength)
        }
    }
}

impl IdentitySecret {
    /// Generates a new random secret identity.
    pub fn generate() -> Self {
        Self(rand::thread_rng().gen())
    }

    /// Returns the public half of this secret identity.
    pub fn public(&self) -> IdentityPublic {
        let seed = ed25519_compact::Seed::new(self.0);
        let pair = ed25519_compact::KeyPair::from_seed(seed);
        let public_key = pair.pk;
        IdentityPublic(*public_key)
    }

    /// Signs a message, returning a signature.
    pub fn sign(&self, msg: &[u8]) -> Bytes {
        let seed = ed25519_compact::Seed::new(self.0);
        let pair = ed25519_compact::KeyPair::from_seed(seed);
        pair.sk.sign(msg, None).to_vec().into()
    }
}

impl IdentitySecret {
    /// Convert from bytes representation
    pub fn from_bytes(b: &[u8; 32]) -> Self {
        Self(*b)
    }

    /// View as bytes representation
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// An Earendil node fingerprint, uniquely identifying a relay or client.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Ord, Eq, Hash, Serialize, Deserialize)]
pub struct Fingerprint([u8; 20]);

impl Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let b64 = base32::encode(Alphabet::Crockford, &self.0).to_lowercase();
        write!(f, "{}", b64)
    }
}

impl FromStr for Fingerprint {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = base32::decode(Alphabet::Crockford, s).context("could not decode base32")?;
        if bytes.len() == 20 {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&bytes);
            Ok(Fingerprint(arr))
        } else {
            Err(anyhow::anyhow!("Invalid fingerprint length"))
        }
    }
}

impl Fingerprint {
    /// Convert from bytes representation
    pub fn from_bytes(b: &[u8; 20]) -> Self {
        Self(*b)
    }

    /// View as bytes representation
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}
