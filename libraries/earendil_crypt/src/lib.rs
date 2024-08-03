use std::{
    fmt::{self, Debug, Display, Formatter},
    str::FromStr,
};

use anyhow::Context;
use argon2::Argon2;
use arrayref::array_ref;
use base32::Alphabet;
use base64::{engine::general_purpose, Engine as _};
use bytemuck::{Pod, Zeroable};
use bytes::Bytes;
use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Derive a key from a human-readable seed. Uses Argon2.
pub fn kdf_from_human(human: &str, salt: &str) -> [u8; 32] {
    let mut output_key_material = [0u8; 32];
    Argon2::default()
        .hash_password_into(human.as_bytes(), salt.as_bytes(), &mut output_key_material)
        .unwrap();
    output_key_material
}

#[derive(Error, Debug, Deserialize, Serialize)]
pub enum VerifyError {
    #[error("The signature is corrupt")]
    SignatureCorrupt,

    #[error("The signature mismatches")]
    SignatureMismatch,
}
/// The public half of an "identity" on the network.
///
/// Underlying representation is a Ed25519 public key.
#[derive(Serialize, Debug, Deserialize, Clone, Copy, PartialEq, PartialOrd, Ord, Eq)]
pub struct HavenIdentityPublic([u8; 32]);

impl TryFrom<Vec<u8>> for HavenIdentityPublic {
    type Error = Vec<u8>;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl AsRef<[u8]> for HavenIdentityPublic {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl HavenIdentityPublic {
    /// Verifies a message supposedly signed by this key.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), VerifyError> {
        let pk = ed25519_consensus::VerificationKeyBytes::from(self.0);
        let pk = ed25519_consensus::VerificationKey::try_from(pk)
            .map_err(|_| VerifyError::SignatureCorrupt)?;
        let sig: [u8; 64] = sig.try_into().map_err(|_| VerifyError::SignatureCorrupt)?;
        let sig = ed25519_consensus::Signature::from(sig);

        pk.verify(&sig, msg)
            .map_err(|_| VerifyError::SignatureMismatch)
    }

    /// The hash-based fingerprint of this identity.
    pub fn fingerprint(&self) -> HavenFingerprint {
        let hash = blake3::keyed_hash(b"fingerprint_____________________", &self.0);
        HavenFingerprint::from_bytes(array_ref![hash.as_bytes(), 0, 20])
    }
}

/// The secret half of an "identity" on the network.
///
/// Underlying representation is a Ed25519 "seed".
#[derive(Serialize, Deserialize, Clone, PartialEq, PartialOrd, Ord, Eq, Copy, Hash, Debug)]
pub struct HavenIdentitySecret([u8; 32]);

impl FromStr for HavenIdentitySecret {
    type Err = base64::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded = general_purpose::STANDARD.decode(s)?;
        let decoded_len = decoded.len();
        if decoded_len == 32 {
            let mut array = [0u8; 32];
            array.copy_from_slice(&decoded);
            Ok(HavenIdentitySecret(array))
        } else {
            Err(base64::DecodeError::InvalidLength(decoded_len))
        }
    }
}

impl HavenIdentitySecret {
    /// Derive an identity from a human-readable seed.
    pub fn from_seed(id_seed: &str) -> Self {
        HavenIdentitySecret::from_bytes(&kdf_from_human(id_seed, "identity_kdf_salt"))
    }

    /// Generates a new random secret identity.
    pub fn generate() -> Self {
        Self(rand::thread_rng().gen())
    }

    /// Returns the public half of this secret identity.
    pub fn public(&self) -> HavenIdentityPublic {
        let sk = ed25519_consensus::SigningKey::from(self.0);
        HavenIdentityPublic(sk.verification_key().to_bytes())
    }

    /// Signs a message, returning a signature.
    pub fn sign(&self, msg: &[u8]) -> Bytes {
        let sk = ed25519_consensus::SigningKey::from(self.0);
        sk.sign(msg).to_bytes().to_vec().into()
    }

    /// Convert from bytes representation
    pub fn from_bytes(b: &[u8; 32]) -> Self {
        Self(*b)
    }

    /// View as bytes representation
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A haven fingerprint is used to uniquely identify Earendil havens
#[repr(C)]
#[derive(
    Clone, Copy, PartialEq, PartialOrd, Ord, Eq, Hash, Serialize, Deserialize, Pod, Zeroable,
)]
pub struct HavenFingerprint([u8; 20]);

impl Display for HavenFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let b64 = base32::encode(Alphabet::Crockford, &self.0).to_lowercase();
        write!(f, "{}", b64)
    }
}

impl Debug for HavenFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let b64 = base32::encode(Alphabet::Crockford, &self.0).to_lowercase();
        write!(f, "{}", b64)
    }
}

impl FromStr for HavenFingerprint {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = base32::decode(Alphabet::Crockford, s).context("could not decode base32")?;
        if bytes.len() == 20 {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&bytes);
            Ok(HavenFingerprint(arr))
        } else {
            Err(anyhow::anyhow!("Invalid haven fingerprint length"))
        }
    }
}

impl HavenFingerprint {
    /// Convert from bytes representation
    pub fn from_bytes(b: &[u8; 20]) -> Self {
        Self(*b)
    }

    /// View as bytes representation
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

#[derive(Copy, Clone, Deserialize, Serialize, Hash, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub struct HavenEndpoint {
    pub fingerprint: HavenFingerprint,
    pub port: u16,
}

impl HavenEndpoint {
    pub fn new(fingerprint: HavenFingerprint, port: u16) -> Self {
        Self { fingerprint, port }
    }
}

impl Display for HavenEndpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.fingerprint, self.port)
    }
}

impl FromStr for HavenEndpoint {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("invalid haven endpoint format"));
        }
        let fingerprint = HavenFingerprint::from_str(parts[0])?;
        let port = u16::from_str(parts[1])?;
        Ok(HavenEndpoint::new(fingerprint, port))
    }
}

/// The public half of a "relay identity" on the network.
///
/// Underlying representation is a Ed25519 public key.
#[derive(Serialize, Debug, Deserialize, Clone, Copy, PartialEq, PartialOrd, Ord, Eq)]
pub struct RelayIdentityPublic([u8; 32]);

impl TryFrom<Vec<u8>> for RelayIdentityPublic {
    type Error = Vec<u8>;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl AsRef<[u8]> for RelayIdentityPublic {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl RelayIdentityPublic {
    /// Verifies a message supposedly signed by this key.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), VerifyError> {
        let pk = ed25519_consensus::VerificationKeyBytes::from(self.0);
        let pk = ed25519_consensus::VerificationKey::try_from(pk)
            .map_err(|_| VerifyError::SignatureCorrupt)?;
        let sig: [u8; 64] = sig.try_into().map_err(|_| VerifyError::SignatureCorrupt)?;
        let sig = ed25519_consensus::Signature::from(sig);

        pk.verify(&sig, msg)
            .map_err(|_| VerifyError::SignatureMismatch)
    }

    /// The hash-based fingerprint of this identity.
    pub fn fingerprint(&self) -> RelayFingerprint {
        let hash = blake3::keyed_hash(b"fingerprint_____________________", &self.0);
        RelayFingerprint::from_bytes(hash.as_bytes())
    }
}

/// The secret half of a "relay identity" on the network.
///
/// Underlying representation is a Ed25519 "seed".
#[derive(Serialize, Deserialize, Clone, PartialEq, PartialOrd, Ord, Eq, Copy, Hash, Debug)]
pub struct RelayIdentitySecret([u8; 32]);

impl FromStr for RelayIdentitySecret {
    type Err = base64::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded = general_purpose::STANDARD.decode(s)?;
        let decoded_len = decoded.len();
        if decoded_len == 32 {
            let mut array = [0u8; 32];
            array.copy_from_slice(&decoded);
            Ok(RelayIdentitySecret(array))
        } else {
            Err(base64::DecodeError::InvalidLength(decoded_len))
        }
    }
}

impl RelayIdentitySecret {
    /// Derive an identity from a human-readable seed.
    pub fn from_seed(id_seed: &str) -> Self {
        RelayIdentitySecret::from_bytes(&kdf_from_human(id_seed, "identity_kdf_salt"))
    }

    /// Generates a new random secret identity.
    pub fn generate() -> Self {
        Self(rand::thread_rng().gen())
    }

    /// Returns the public half of this secret identity.
    pub fn public(&self) -> RelayIdentityPublic {
        let sk = ed25519_consensus::SigningKey::from(self.0);
        RelayIdentityPublic(sk.verification_key().to_bytes())
    }

    /// Signs a message, returning a signature.
    pub fn sign(&self, msg: &[u8]) -> Bytes {
        let sk = ed25519_consensus::SigningKey::from(self.0);
        sk.sign(msg).to_bytes().to_vec().into()
    }

    /// Convert from bytes representation
    pub fn from_bytes(b: &[u8; 32]) -> Self {
        Self(*b)
    }

    /// View as bytes representation
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// An Earendil node fingerprint, uniquely identifying a relay.
#[repr(C)]
#[derive(
    Clone, Copy, PartialEq, PartialOrd, Ord, Eq, Hash, Serialize, Deserialize, Pod, Zeroable,
)]
pub struct RelayFingerprint([u8; 32]);
impl Display for RelayFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let hex_str = hex::encode(self.0).to_lowercase(); // Convert bytes to hex string
        write!(f, "{}", hex_str)
    }
}

impl Debug for RelayFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let hex_str = hex::encode(self.0).to_lowercase(); // Convert bytes to hex string
        write!(f, "{}", hex_str)
    }
}

impl FromStr for RelayFingerprint {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).context("could not decode hex")?;
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(RelayFingerprint(arr))
        } else {
            Err(anyhow::anyhow!("Invalid relay fingerprint length"))
        }
    }
}

impl RelayFingerprint {
    /// Convert from bytes representation
    pub fn from_bytes(b: &[u8; 32]) -> Self {
        Self(*b)
    }

    /// View as bytes representation
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[repr(C)]
#[derive(
    Clone, Copy, PartialEq, PartialOrd, Ord, Eq, Hash, Serialize, Deserialize, Pod, Zeroable,
)]
pub struct AnonEndpoint(pub [u8; 16]);

impl AnonEndpoint {
    pub fn random() -> Self {
        let new_anon_id: [u8; 16] = rand::thread_rng().gen();
        AnonEndpoint(new_anon_id)
    }
}

impl Display for AnonEndpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let hex_string = hex::encode(self.0);
        write!(f, "ANON-{}", hex_string)
    }
}

impl Debug for AnonEndpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let hex_string = hex::encode(self.0);
        write!(f, "ANON-{}", hex_string)
    }
}

#[derive(Copy, Clone, Deserialize, Serialize, Hash, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub struct RelayEndpoint {
    pub fingerprint: RelayFingerprint,
    pub dock: u32,
}

impl RelayEndpoint {
    pub fn new(fingerprint: RelayFingerprint, dock: u32) -> Self {
        Self { fingerprint, dock }
    }
}

impl Display for RelayEndpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.fingerprint, self.dock)
    }
}

impl FromStr for RelayEndpoint {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("invalid relay endpoint format"));
        }
        let fingerprint = RelayFingerprint::from_str(parts[0])?;
        let dock = u32::from_str(parts[1])?;
        Ok(RelayEndpoint::new(fingerprint, dock))
    }
}

pub type ClientId = u64;

#[derive(Clone, Copy, Eq, PartialEq, Debug, Hash)]
pub enum RemoteId {
    Relay(RelayFingerprint),
    Anon(AnonEndpoint),
}
