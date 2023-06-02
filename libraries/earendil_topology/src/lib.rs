use std::collections::{HashMap, HashSet};

use arrayref::array_ref;
use bytes::Bytes;
use earendil_packet::Fingerprint;
use serde::{Deserialize, Serialize};
use stdcode::StdcodeSerializeExt;

/// A full, indexed representation of the Earendil relay graph. Includes info about:
/// - Which fingerprints are adjacent to which fingerprints
/// - What signing keys and midterm keys does each fingerprint have
pub struct RelayGraph {
    unalloc_id: u64,
    fp_to_id: HashMap<Fingerprint, u64>,
    adjacency: HashMap<u64, HashSet<u64>>,
    documents: HashMap<(u64, u64), AdjacencyDescriptor>,
}

impl RelayGraph {
    pub fn alloc_id(&mut self, fp: &Fingerprint) -> u64 {
        if let Some(val) = self.fp_to_id.get(fp) {
            *val
        } else {
            let id = self.unalloc_id;
            self.unalloc_id += 1;
            self.fp_to_id.insert(*fp, id);
            id
        }
    }

    pub fn id(&self, fp: &Fingerprint) -> Option<u64> {
        self.fp_to_id.get(fp).copied()
    }
}

/// An adjacency descriptor, signed by both sides. "Left" is always the one with the smaller fingerprint. Also carries the IdentityPublics of everyone along.
///
/// The signatures are computed with respect to the descriptor with the signature-fields zeroed out.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq)]
pub struct AdjacencyDescriptor {
    pub left: Fingerprint,
    pub right: Fingerprint,
    pub left_idpk: IdentityPublic,
    pub right_idpk: IdentityPublic,
    pub left_sig: Bytes,
    pub right_sig: Bytes,
}

/// Validates an adjacency descriptor. A valid adjacency descriptor must:
/// - Have identities that actually correspond to the fingerprints
/// - Have valid signatures

/// The public half of an "identity" on the network.
///
/// Underlying representation is a Ed25519 public key.
#[derive(Serialize, Debug, Deserialize, Clone, Copy, PartialEq, PartialOrd, Ord, Eq)]
pub struct IdentityPublic([u8; 32]);

impl IdentityPublic {
    /// Verifies a message supposedly signed by this key.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        if let Ok(pk) = ed25519_compact::PublicKey::from_slice(&self.0) {
            if let Ok(sig) = ed25519_compact::Signature::from_slice(sig) {
                return pk.verify(msg, &sig).is_ok();
            }
        }
        false
    }

    /// The hash-based fingerprint of this identity.
    pub fn fingerprint(&self) -> Fingerprint {
        let hash = blake3::keyed_hash(b"fingerprint_____________________", &self.stdcode());
        Fingerprint::from_bytes(array_ref![hash.as_bytes(), 0, 20])
    }
}

/// The secret half of an "dentity" on the network.
///
/// Underlying representation is a Ed25519 "seed".
#[derive(Serialize, Deserialize, Clone, PartialEq, PartialOrd, Ord, Eq)]
pub struct IdentitySecret([u8; 32]);
