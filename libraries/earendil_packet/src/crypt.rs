use arrayref::array_ref;
use bytes::Bytes;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
use thiserror::Error;

/// An onion-routing public key, based on x25519.
pub struct OnionPublic(ed25519_compact::x25519::PublicKey);

impl OnionPublic {
    /// Return the bytes representation.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// An onion-routing secret key, based on x25519.
pub struct OnionSecret(ed25519_compact::x25519::KeyPair);

impl OnionSecret {
    /// Generates a secret key.
    pub fn generate() -> Self {
        Self(ed25519_compact::x25519::KeyPair::generate())
    }

    /// Returns the public key of this secret key.
    pub fn public(&self) -> OnionPublic {
        OnionPublic(self.0.pk)
    }

    /// Derive the shared secret, given somebody else's public key.
    pub fn shared_secret(&self, theirs: &OnionPublic) -> [u8; 32] {
        theirs.0.dh(&self.0.sk).map(|d| *d).unwrap_or_default()
    }
}

/// AEAD encryption/decryption key
pub struct AeadKey {
    inner: ChaCha20Poly1305,
}

impl AeadKey {
    /// Creates a new AeadKey from raw bytes.
    pub fn from_bytes(bts: &[u8; 32]) -> Self {
        Self {
            inner: ChaCha20Poly1305::new(bts.into()),
        }
    }

    /// Seals a message with this key.
    pub fn seal(&self, nonce: &[u8; 12], plain: &[u8]) -> Bytes {
        self.inner.encrypt(nonce.into(), plain).unwrap().into()
    }

    /// Opens a message that was sealed with this key.
    pub fn open(&self, nonce: &[u8; 12], ctext: &[u8]) -> Result<Bytes, AeadError> {
        self.inner
            .decrypt(nonce.into(), ctext)
            .ok()
            .map(|f| f.into())
            .ok_or(AeadError::DecryptionFailed)
    }
}

#[derive(Error, Debug, Clone, Copy, PartialEq, PartialOrd, Ord, Eq)]
pub enum AeadError {
    #[error("decryption failed")]
    DecryptionFailed,
}

/// Encrypts a message, with integrity protection, so that only the owner of a particular X25519 secret key can read it.
pub fn box_encrypt(
    message: &[u8],
    sender_sk: &OnionSecret,
    recipient_public_key: &OnionPublic,
) -> Bytes {
    let sender_pk = sender_sk.public();
    let shared_secret = sender_sk.shared_secret(recipient_public_key);
    let aead_key = AeadKey::from_bytes(blake3::hash(&shared_secret).as_bytes());
    let nonce = [0u8; 12]; // all-zero nonce
    let encrypted_message = aead_key.seal(&nonce, message);

    let mut result = sender_pk.as_bytes().to_vec();
    result.extend_from_slice(&encrypted_message);
    result.into()
}

/// Decrypts a message encrypted with box_encrypt, given the recipient's secret key.
pub fn box_decrypt(
    encrypted_message: &[u8],
    recipient_secret_key: &OnionSecret,
) -> Result<Bytes, AeadError> {
    if encrypted_message.len() < 32 {
        return Err(AeadError::DecryptionFailed);
    }

    let sender_public_key = OnionPublic(ed25519_compact::x25519::PublicKey::new(*array_ref![
        encrypted_message,
        0,
        32
    ]));
    let shared_secret = recipient_secret_key.shared_secret(&sender_public_key);
    let aead_key = AeadKey::from_bytes(blake3::hash(&shared_secret).as_bytes());
    let nonce = [0u8; 12]; // all-zero nonce
    aead_key.open(&nonce, &encrypted_message[32..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_secret() {
        let alice_secret_key = OnionSecret::generate();
        let alice_public_key = alice_secret_key.public();
        let bob_secret_key = OnionSecret::generate();
        let bob_public_key = bob_secret_key.public();

        let shared_secret_alice = alice_secret_key.shared_secret(&bob_public_key);
        let shared_secret_bob = bob_secret_key.shared_secret(&alice_public_key);

        assert_eq!(shared_secret_alice, shared_secret_bob);
    }

    #[test]
    fn aead_encryption_decryption() {
        let key_raw = [42; 32];
        let key = AeadKey::from_bytes(&key_raw);
        let nonce = [1; 12];
        let message = b"Hello, world!";

        let ciphertext = key.seal(&nonce, message);
        let decrypted = key.open(&nonce, &ciphertext).unwrap();

        assert_eq!(message, &decrypted[..]);
    }

    #[test]
    fn box_encrypt_decrypt() {
        let message = b"Super secret message";
        let sender_sk = OnionSecret::generate();
        let recipient_sk = OnionSecret::generate();
        let recipient_pk = recipient_sk.public();

        let encrypted_message = box_encrypt(&message[..], &sender_sk, &recipient_pk);

        let decrypted_message = box_decrypt(&encrypted_message[..], &recipient_sk).unwrap();
        assert_eq!(message, &decrypted_message[..]);
    }
}
