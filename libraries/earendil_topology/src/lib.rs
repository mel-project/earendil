use std::collections::{HashMap, HashSet, VecDeque};

use arrayref::array_ref;
use bytes::Bytes;
use earendil_packet::{crypt::OnionPublic, Fingerprint};
use indexmap::IndexMap;
use rand::Rng;
use serde::{Deserialize, Serialize};
use stdcode::StdcodeSerializeExt;

/// A full, indexed representation of the Earendil relay graph. Includes info about:
/// - Which fingerprints are adjacent to which fingerprints
/// - What signing keys and midterm keys does each fingerprint have
#[derive(Default)]
pub struct RelayGraph {
    unalloc_id: u64,
    fp_to_id: HashMap<Fingerprint, u64>,
    id_to_fp: HashMap<u64, Fingerprint>,
    id_to_descriptor: HashMap<u64, IdentityDescriptor>,
    adjacency: HashMap<u64, HashSet<u64>>,
    documents: IndexMap<(u64, u64), AdjacencyDescriptor>,
}

impl RelayGraph {
    /// Creates a new RelayGraph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Looks up the identity descriptor of a fingerprint.
    pub fn identity(&self, fingerprint: &Fingerprint) -> Option<IdentityDescriptor> {
        let id = self.id(fingerprint)?;
        self.id_to_descriptor.get(&id).cloned()
    }

    /// Inserts an identity descriptor. Verifies its self-consistency, and returns false if it's not valid.
    pub fn insert_identity(&mut self, identity: IdentityDescriptor) -> bool {
        if !identity
            .identity_pk
            .verify(identity.to_sign().as_bytes(), &identity.sig)
        {
            return false;
        }
        let id = self.alloc_id(&identity.identity_pk.fingerprint());
        self.id_to_descriptor.insert(id, identity);
        true
    }

    /// Inserts an adjacency descriptor. Verifies the descriptor and returns false if it's not valid.
    /// Returns true if the descriptor was inserted successfully.
    pub fn insert_adjacency(&mut self, adjacency: AdjacencyDescriptor) -> bool {
        if !self.verify_adjacency(&adjacency) {
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

    /// Returns the adjacencies next to the given Fingerprint.
    /// None is returned if the given Fingerprint is not present in the graph.
    pub fn adjacencies(
        &self,
        fp: &Fingerprint,
    ) -> Option<impl Iterator<Item = AdjacencyDescriptor> + '_> {
        let fp = *fp;
        let id = self.id(&fp)?;
        Some(self.adjacency[&id].iter().copied().map(move |neigh_id| {
            let neigh = self.id_to_fp[&neigh_id];
            if fp < neigh {
                self.documents[&(id, neigh_id)].clone()
            } else {
                self.documents[&(neigh_id, id)].clone()
            }
        }))
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

    fn verify_adjacency(&self, adj: &AdjacencyDescriptor) -> bool {
        if adj.left >= adj.right {
            return false;
        }

        let left_idpk = if let Some(left) = self.identity(&adj.left) {
            left.identity_pk
        } else {
            return false;
        };

        let right_idpk = if let Some(right) = self.identity(&adj.right) {
            right.identity_pk
        } else {
            return false;
        };

        let to_sign = adj.to_sign();

        left_idpk.verify(to_sign.as_bytes(), &adj.left_sig)
            && right_idpk.verify(to_sign.as_bytes(), &adj.right_sig)
    }
}

/// An adjacency descriptor, signed by both sides. "Left" is always the one with the smaller fingerprint. Also carries the IdentityPublics of everyone along.
///
/// The signatures are computed with respect to the descriptor with the signature-fields zeroed out.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdjacencyDescriptor {
    pub left: Fingerprint,
    pub right: Fingerprint,

    pub left_sig: Bytes,
    pub right_sig: Bytes,

    pub unix_timestamp: u64,
}

impl AdjacencyDescriptor {
    /// The value that the signatures are supposed to be computed against.
    pub fn to_sign(&self) -> blake3::Hash {
        let mut this = self.clone();
        this.left_sig = Bytes::new();
        this.right_sig = Bytes::new();
        blake3::keyed_hash(b"adjacency_descriptor____________", &this.stdcode())
    }
}

/// An identity descriptor, signed by the owner of an identity. Declares that the identity owns a particular onion key, as well as implicitly
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityDescriptor {
    pub identity_pk: IdentityPublic,
    pub onion_pk: OnionPublic,

    pub sig: Bytes,

    pub unix_timestamp: u64,
}

impl IdentityDescriptor {
    /// The value that the signatures are supposed to be computed against.
    pub fn to_sign(&self) -> blake3::Hash {
        let mut this = self.clone();
        this.sig = Bytes::new();
        blake3::keyed_hash(b"identity_descriptor_____________", &this.stdcode())
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
