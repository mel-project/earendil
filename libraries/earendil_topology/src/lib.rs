use std::collections::{HashMap, HashSet, VecDeque};

use arrayref::array_ref;
use bytes::Bytes;
use earendil_packet::Fingerprint;
use indexmap::IndexMap;
use rand::Rng;
use serde::{Deserialize, Serialize};
use stdcode::StdcodeSerializeExt;

/// A full, indexed representation of the Earendil relay graph. Includes info about:
/// - Which fingerprints are adjacent to which fingerprints
/// - What signing keys and midterm keys does each fingerprint have
#[derive(Serialize, Deserialize, Default)]
pub struct RelayGraph {
    unalloc_id: u64,
    fp_to_id: HashMap<Fingerprint, u64>,
    id_to_fp: HashMap<u64, Fingerprint>,
    adjacency: HashMap<u64, HashSet<u64>>,
    documents: IndexMap<(u64, u64), AdjacencyDescriptor>,
}

impl RelayGraph {
    /// Creates a new RelayGraph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts an adjacency descriptor. Verifies the descriptor and returns false if it's not valid.
    /// Returns true if the descriptor was inserted successfully.
    pub fn insert_adjacency(&mut self, adjacency: AdjacencyDescriptor) -> bool {
        if !adjacency.verify() {
            return false;
        }

        let left_fp = &adjacency.left;
        let right_fp = &adjacency.right;
        let left_id = self.alloc_id(left_fp);
        let right_id = self.alloc_id(right_fp);

        self.documents.insert((left_id, right_id), adjacency);

        self.adjacency
            .entry(left_id)
            .or_insert_with(HashSet::new)
            .insert(right_id);
        self.adjacency
            .entry(right_id)
            .or_insert_with(HashSet::new)
            .insert(left_id);

        true
    }

    /// Returns the adjacent Fingerprints to the given Fingerprint.
    /// None is returned if the given Fingerprint is not present in the graph.
    pub fn neighbors(&self, fp: &Fingerprint) -> Option<impl Iterator<Item = Fingerprint> + '_> {
        self.id(fp).map(move |id| {
            self.adjacency[&id].iter().filter_map(move |adj_id| {
                self.fp_to_id
                    .iter()
                    .find(|&(_, value)| value == adj_id)
                    .map(|(key, _)| *key)
            })
        })
    }

    /// Picks a random AdjacencyDescriptor from the graph.
    pub fn random_adjacency(&self) -> Option<AdjacencyDescriptor> {
        if self.documents.is_empty() {
            return None;
        }
        self.documents
            .get_index(rand::thread_rng().gen_range(0..self.documents.len()))
            .map(|v| v.1.clone())
    }

    /// Finds the shortest path between two Fingerprints.
    /// Returns a Vec of Fingerprint instances representing the shortest path or None if no path exists.
    pub fn find_shortest_path(
        &self,
        start_fp: &Fingerprint,
        end_fp: &Fingerprint,
    ) -> Option<Vec<Fingerprint>> {
        let start_id = self.id(start_fp)?;
        let end_id = self.id(end_fp)?;

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut path = HashMap::new();

        visited.insert(start_id);
        queue.push_back(start_id);

        while let Some(current_id) = queue.pop_front() {
            if current_id == end_id {
                let mut result = Vec::new();
                let mut current_id = current_id;

                while let Some(prev_id) = path.get(&current_id) {
                    result.push(self.id_to_fp[&current_id]);
                    current_id = *prev_id;
                }

                result.push(self.id_to_fp[&start_id]);
                result.reverse();
                return Some(result);
            }

            for neighbor_id in self.adjacency.get(&current_id)?.iter() {
                if !visited.contains(neighbor_id) {
                    visited.insert(*neighbor_id);
                    path.insert(*neighbor_id, current_id);
                    queue.push_back(*neighbor_id);
                }
            }
        }

        None
    }

    fn alloc_id(&mut self, fp: &Fingerprint) -> u64 {
        if let Some(val) = self.fp_to_id.get(fp) {
            *val
        } else {
            let id = self.unalloc_id;
            self.unalloc_id += 1;
            self.fp_to_id.insert(*fp, id);
            self.id_to_fp.insert(id, *fp);
            id
        }
    }

    fn id(&self, fp: &Fingerprint) -> Option<u64> {
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

impl AdjacencyDescriptor {
    /// Verifies the invariants of the adjacency descriptor. A valid adjacency descriptor must:
    /// - Have identities that actually correspond to the fingerprints
    /// - Have valid signatures
    pub fn verify(&self) -> bool {
        let left_fp = self.left_idpk.fingerprint();
        let right_fp = self.right_idpk.fingerprint();

        if left_fp >= right_fp {
            return false;
        }

        let mut signed_descriptor = self.clone();
        signed_descriptor.left_sig = Bytes::new();
        signed_descriptor.right_sig = Bytes::new();

        let signed_descriptor_bytes = signed_descriptor.stdcode();

        self.left_idpk
            .verify(&signed_descriptor_bytes, &self.left_sig)
            && self
                .right_idpk
                .verify(&signed_descriptor_bytes, &self.right_sig)
    }
}

/// Validates an adjacency descriptor. A valid adjacency descriptor must:
/// - Have identities that actually correspond to the fingerprints
/// - Have valid signatures

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

/// The secret half of an "identity" on the network.
///
/// Underlying representation is a Ed25519 "seed".
#[derive(Serialize, Deserialize, Clone, PartialEq, PartialOrd, Ord, Eq)]
pub struct IdentitySecret([u8; 32]);

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
