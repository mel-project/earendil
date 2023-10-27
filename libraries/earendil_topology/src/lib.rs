use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::{SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use earendil_crypt::{Fingerprint, IdentityPublic, IdentitySecret, VerifyError};
use earendil_packet::crypt::{OnionPublic, OnionSecret};
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

// Update the AdjacencyError enum with more specific cases
#[derive(thiserror::Error, Debug)]
pub enum AdjacencyError {
    #[error("Left fingerprint is not smaller than the right fingerprint")]
    LeftNotSmallerThanRight,

    #[error("Left identity not found in the graph")]
    LeftIdentityNotFound,

    #[error("Right identity not found in the graph")]
    RightIdentityNotFound,

    #[error("Invalid signature(s) in the adjacency descriptor")]
    InvalidSignatures,
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

    /// Inserts an identity descriptor. Verifies its self-consistency.
    pub fn insert_identity(&mut self, identity: IdentityDescriptor) -> Result<(), VerifyError> {
        identity
            .identity_pk
            .verify(identity.to_sign().as_bytes(), &identity.sig)?;
        let id = self.alloc_id(&identity.identity_pk.fingerprint());
        self.id_to_descriptor.insert(id, identity);
        Ok(())
    }

    /// Inserts an adjacency descriptor. Verifies the descriptor and returns false if it's not valid.
    /// Returns true if the descriptor was inserted successfully.
    pub fn insert_adjacency(
        &mut self,
        adjacency: AdjacencyDescriptor,
    ) -> Result<(), AdjacencyError> {
        self.verify_adjacency(&adjacency)?;

        let left_fp = &adjacency.left;
        let right_fp = &adjacency.right;
        let left_id = self.alloc_id(left_fp);
        let right_id = self.alloc_id(right_fp);

        self.documents.insert((left_id, right_id), adjacency);

        self.adjacency.entry(left_id).or_default().insert(right_id);
        self.adjacency.entry(right_id).or_default().insert(left_id);

        Ok(())
    }

    /// Returns the adjacencies next to the given Fingerprint.
    /// None is returned if the given Fingerprint is not present in the graph.
    pub fn adjacencies(
        &self,
        fp: &Fingerprint,
    ) -> Option<impl Iterator<Item = AdjacencyDescriptor> + '_> {
        let fp = *fp;
        let id = self.id(&fp)?;
        Some(
            self.adjacency
                .get(&id)?
                .iter()
                .copied()
                .map(move |neigh_id| {
                    let neigh = self.id_to_fp[&neigh_id];
                    if fp < neigh {
                        self.documents[&(id, neigh_id)].clone()
                    } else {
                        self.documents[&(neigh_id, id)].clone()
                    }
                }),
        )
    }

    /// Returns all the adjacencies.
    pub fn all_adjacencies(&self) -> impl Iterator<Item = AdjacencyDescriptor> + '_ {
        self.documents.values().cloned()
    }

    /// Returns all the nodes.
    pub fn all_nodes(&self) -> impl Iterator<Item = Fingerprint> + '_ {
        self.fp_to_id.keys().copied()
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

    fn verify_adjacency(&self, adj: &AdjacencyDescriptor) -> Result<(), AdjacencyError> {
        if adj.left >= adj.right {
            return Err(AdjacencyError::LeftNotSmallerThanRight);
        }

        let left_idpk = if let Some(left) = self.identity(&adj.left) {
            left.identity_pk
        } else {
            return Err(AdjacencyError::LeftIdentityNotFound);
        };

        let right_idpk = if let Some(right) = self.identity(&adj.right) {
            right.identity_pk
        } else {
            return Err(AdjacencyError::RightIdentityNotFound);
        };

        let to_sign = adj.to_sign();

        let left_valid = left_idpk.verify(to_sign.as_bytes(), &adj.left_sig).is_ok();
        let right_valid = right_idpk
            .verify(to_sign.as_bytes(), &adj.right_sig)
            .is_ok();

        if !left_valid || !right_valid {
            return Err(AdjacencyError::InvalidSignatures);
        }

        Ok(())
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
    /// Creates an IdentityDescriptor from our own IdentitySecret
    pub fn new(my_identity: &IdentitySecret, my_onion: &OnionSecret) -> Self {
        let identity_pk = my_identity.public();
        let onion_pk = my_onion.public();
        let mut descr = IdentityDescriptor {
            identity_pk,
            onion_pk,
            sig: Bytes::new(),
            unix_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        descr.sig = my_identity.sign(descr.to_sign().as_bytes());
        descr
    }

    /// The value that the signatures are supposed to be computed against.
    pub fn to_sign(&self) -> blake3::Hash {
        let mut this = self.clone();
        this.sig = Bytes::new();
        blake3::keyed_hash(b"identity_descriptor_____________", &this.stdcode())
    }
}
