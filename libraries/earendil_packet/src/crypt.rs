
use arrayref::array_ref;
use chacha20::{
    ChaCha20,
    cipher::{KeyIvInit, StreamCipher},
};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
use earendil_crypt::{DhPublic, DhSecret};
use thiserror::Error;

/// AEAD encryption/decryption key
#[derive(Clone)]
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
    pub fn seal(&self, nonce: &[u8; 12], plain: &[u8]) -> Vec<u8> {
        self.inner.encrypt(nonce.into(), plain).unwrap()
    }

    /// Opens a message that was sealed with this key.
    pub fn open(&self, nonce: &[u8; 12], ctext: &[u8]) -> Result<Vec<u8>, AeadError> {
        self.inner
            .decrypt(nonce.into(), ctext)
            .ok()
            .ok_or(AeadError::DecryptionFailed)
    }
}

#[derive(Error, Debug, Clone, Copy, PartialEq, PartialOrd, Ord, Eq)]
pub enum AeadError {
    #[error("decryption failed")]
    DecryptionFailed,
}

pub const BOX_OVERHEAD: usize = 48;

/// Encrypts a message, with integrity protection, so that only the owner of a particular X25519 secret key can read it. Does not identify the sender.
///
/// **Always** generates a fresh ephemeral keypair, returning it alongside the ciphertext.
pub fn box_encrypt(message: &[u8], recipient_pk: &DhPublic) -> (Vec<u8>, DhSecret) {
    let sender_sk = DhSecret::generate();
    let sender_pk = sender_sk.public();
    let shared_secret = sender_sk.shared_secret(recipient_pk);
    let aead_key = AeadKey::from_bytes(blake3::hash(&shared_secret).as_bytes());
    let nonce = [0u8; 12];
    let encrypted_message = aead_key.seal(&nonce, message);

    let mut result = sender_pk.as_bytes().to_vec();
    result.extend_from_slice(&encrypted_message);
    (result, sender_sk)
}

/// Decrypts a message encrypted with anonbox_encrypt, given the recipient's secret key.
///
/// Returns the ciphertext as well as the sending ephemeral PK.
pub fn box_decrypt(
    encrypted_message: &[u8],
    recipient_sk: &DhSecret,
) -> Result<(Vec<u8>, DhPublic), AeadError> {
    if encrypted_message.len() < 32 {
        return Err(AeadError::DecryptionFailed);
    }

    let sender_public_key = DhPublic::from_bytes(array_ref![encrypted_message, 0, 32]);
    let shared_secret = recipient_sk.shared_secret(&sender_public_key);
    let aead_key = AeadKey::from_bytes(blake3::hash(&shared_secret).as_bytes());
    let nonce = [0u8; 12]; // all-zero nonce
    Ok((
        aead_key.open(&nonce, &encrypted_message[32..])?,
        sender_public_key,
    ))
}

/// "Dencrypts" an arbitrary byte buffer, in-place, using a stream cipher.
///
/// The underlying algorithm is ChaCha20 (IETF variant).
pub fn stream_dencrypt(key: &[u8; 32], nonce: &[u8; 12], buf: &mut [u8]) {
    let mut cipher = ChaCha20::new(key.into(), nonce.into());
    cipher.apply_keystream(buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onion_public_serialize_deserialize() {
        let secret_key = DhSecret::generate();
        let public_key = secret_key.public();

        let serialized = bincode::serialize(&public_key).unwrap();
        let deserialized: DhPublic = bincode::deserialize(&serialized).unwrap();

        assert_eq!(public_key.as_bytes(), deserialized.as_bytes());
    }

    #[test]
    fn shared_secret() {
        let alice_secret_key = DhSecret::generate();
        let alice_public_key = alice_secret_key.public();
        let bob_secret_key = DhSecret::generate();
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

        let recipient_sk = DhSecret::generate();
        let recipient_pk = recipient_sk.public();

        let (encrypted_message, _) = box_encrypt(&message[..], &recipient_pk);

        let (decrypted_message, _) = box_decrypt(&encrypted_message[..], &recipient_sk).unwrap();
        assert_eq!(message, &decrypted_message[..]);
    }
}
