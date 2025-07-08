use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fmt::Display,
    num::ParseIntError,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use bytemuck::{Pod, Zeroable};
use bytes::Bytes;
use earendil_crypt::{DhPublic, DhSecret};
use earendil_crypt::{
    HavenEndpoint, RelayFingerprint, RelayIdentityPublic, RelayIdentitySecret, VerifyError,
};
use indexmap::IndexMap;
use rand::{Rng, seq::IteratorRandom, thread_rng};
use serde::{Deserialize, Serialize};
use stdcode::StdcodeSerializeExt;
use thiserror::Error;

/// Identifies a specific node in the network, which could be a relay or a client (client_id > 0)
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Pod, Zeroable)]
pub struct NodeAddr {
    pub relay: RelayFingerprint,
    pub client_id: u64,
}

impl NodeAddr {
    pub fn new(relay: RelayFingerprint, client_id: u64) -> Self {
        NodeAddr { relay, client_id }
    }

    pub fn as_bytes(&self) -> &[u8; 40] {
        bytemuck::cast_ref(self)
    }

    pub fn from_bytes(bytes: &[u8; 40]) -> Self {
        *bytemuck::cast_ref(bytes)
    }
}

impl Display for NodeAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "na-{}-{}", self.relay, self.client_id)
    }
}

/// Errors that can occur when parsing a `NodeAddr` from a string.
#[derive(Debug, Error)]
pub enum NodeAddrParseError {
    #[error("invalid NodeAddr format, expected `na-<relay>-<client_id>`")]
    InvalidFormat,

    #[error("invalid relay fingerprint: {0}")]
    InvalidRelayFingerprint(#[source] <RelayFingerprint as FromStr>::Err),

    #[error("invalid client id: {0}")]
    InvalidClientId(ParseIntError),
}

impl FromStr for NodeAddr {
    type Err = NodeAddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(3, '-');
        if parts.next() != Some("na") {
            return Err(NodeAddrParseError::InvalidFormat);
        }

        let relay_str = parts.next().ok_or(NodeAddrParseError::InvalidFormat)?;
        let client_str = parts.next().ok_or(NodeAddrParseError::InvalidFormat)?;

        // Parse the relay fingerprint
        let relay = relay_str
            .parse()
            .map_err(NodeAddrParseError::InvalidRelayFingerprint)?;

        let client_id = client_str
            .parse()
            .map_err(NodeAddrParseError::InvalidClientId)?;

        Ok(NodeAddr { relay, client_id })
    }
}

/// A full, indexed representation of the Earendil relay graph. Includes info about:
/// - Which fingerprints are adjacent to which fingerprints
/// - What signing keys and midterm keys do each fingerprint have
#[derive(Default, Serialize, Deserialize, Clone)]
pub struct RelayGraph {
    unalloc_id: u64,
    fp_to_id: HashMap<RelayFingerprint, u64>,
    id_to_fp: HashMap<u64, RelayFingerprint>,
    id_to_descriptor: HashMap<u64, IdentityDescriptor>,
    adjacency: HashMap<u64, HashSet<u64>>,
    documents: IndexMap<(u64, u64), AdjacencyDescriptor>,
    exits: ExitRegistry,
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
    pub fn identity(&self, fingerprint: RelayFingerprint) -> Option<IdentityDescriptor> {
        // tracing::trace!(
        //     needle = debug(fingerprint),
        //     haystack = debug(self.fp_to_id.iter().collect::<Vec<_>>()),
        //     haystack2 = debug(self.id_to_descriptor.keys().collect::<Vec<_>>()),
        //     "looking up identity"
        // );
        let id = self.id(fingerprint)?;
        self.id_to_descriptor.get(&id).cloned()
    }

    /// Inserts an identity descriptor. Verifies its self-consistency.
    pub fn insert_identity(&mut self, identity: IdentityDescriptor) -> Result<(), VerifyError> {
        // do not insert if we already have a newer copy
        if let Some(existing) = self.identity(identity.identity_pk.fingerprint()) {
            if existing.unix_timestamp > identity.unix_timestamp {
                return Ok(());
            }
        }
        identity.verify()?;
        let relay_fp = identity.identity_pk.fingerprint();
        let id = self.alloc_id(&relay_fp);
        self.id_to_descriptor.insert(id, identity.clone());

        if let Some(exit_info) = identity
            .metadata
            .get("exit_info")
            .and_then(|v| stdcode::deserialize(v).ok())
        {
            self.insert_exit(relay_fp, exit_info);
        }

        tracing::debug!(identity = debug(&identity), "inserted identity");

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

        self.cleanup();
        Ok(())
    }

    /// Returns a list of neighbors to the given Fingerprint.
    pub fn neighbors(
        &self,
        fp: RelayFingerprint,
    ) -> Option<impl Iterator<Item = RelayFingerprint> + '_> {
        let id = self.id(fp)?;
        let neighs = self.adjacency.get(&id)?;
        Some(
            neighs
                .iter()
                .copied()
                .filter_map(move |neigh_id| self.id_to_fp.get(&neigh_id))
                .copied(),
        )
    }

    /// Returns the adjacencies next to the given Fingerprint.
    /// None is returned if the given Fingerprint is not present in the graph.
    pub fn adjacencies(
        &self,
        fp: RelayFingerprint,
    ) -> Option<impl Iterator<Item = AdjacencyDescriptor> + '_> {
        let id = self.id(fp)?;
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
    pub fn all_nodes(&self) -> impl Iterator<Item = RelayFingerprint> + '_ {
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

    /// Picks a certain number of random relays.
    pub fn rand_relays(&self, num: usize) -> Vec<RelayFingerprint> {
        self.all_nodes()
            .filter_map(|n| self.identity(n))
            .map(|id| id.identity_pk.fingerprint())
            .choose_multiple(&mut rand::thread_rng(), num)
    }

    fn insert_exit(&mut self, relay_fp: RelayFingerprint, exit_info: ExitInfo) {
        tracing::debug!(
            relay_fp = display(relay_fp),
            exit_info = debug(&exit_info),
            "inserting exit_info"
        );
        self.exits.add_exit(relay_fp, exit_info);
    }

    pub fn get_exit(&self, relay_fp: &RelayFingerprint) -> Option<&ExitInfo> {
        self.exits.get_exit(relay_fp)
    }

    pub fn get_random_exit_for_port(&self, port: u16) -> Option<(&RelayFingerprint, &ExitInfo)> {
        self.exits.get_random_exit_for_port(port)
    }

    /// Returns a Vec of Fingerprint instances representing the shortest path or None if no path exists.
    /// bypassing any Fingerprint in the blacklist.
    pub fn find_shortest_path(
        &self,
        start_fp: RelayFingerprint,
        end_fp: RelayFingerprint,
    ) -> Option<Vec<RelayFingerprint>> {
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

                // Retrace the path backwards and add the Fingerprint instances to the result
                while let Some(prev_id) = path.get(&current_id) {
                    result.push(self.id_to_fp[&current_id]);
                    current_id = *prev_id;
                }

                result.push(self.id_to_fp[&start_id]);
                result.reverse();
                return Some(result);
            }

            if let Some(neighbors) = self.adjacency.get(&current_id) {
                for neighbor_id in neighbors.iter() {
                    if !visited.contains(neighbor_id) {
                        visited.insert(*neighbor_id);
                        path.insert(*neighbor_id, current_id);
                        queue.push_back(*neighbor_id);
                    }
                }
            }
        }

        None
    }

    // removes all information more than ROUTE_TIMEOUT ago
    fn cleanup(&mut self) {
        const ROUTE_TIMEOUT: u64 = 60 * 60; // e.g., 1 hour in seconds
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let outdated_identities: HashSet<u64> = self
            .id_to_descriptor
            .iter()
            .filter_map(|(&id, descriptor)| {
                if now.saturating_sub(descriptor.unix_timestamp) > ROUTE_TIMEOUT {
                    Some(id)
                } else {
                    None
                }
            })
            .collect();

        for &id in &outdated_identities {
            self.id_to_descriptor.remove(&id);
            if let Some(fp) = self.id_to_fp.remove(&id) {
                self.fp_to_id.remove(&fp);
            }
        }

        let outdated_documents: Vec<(u64, u64)> = self
            .documents
            .iter()
            .filter_map(|(&(left_id, right_id), descriptor)| {
                if outdated_identities.contains(&left_id)
                    || outdated_identities.contains(&right_id)
                    || now.saturating_sub(descriptor.unix_timestamp) > ROUTE_TIMEOUT
                {
                    Some((left_id, right_id))
                } else {
                    None
                }
            })
            .collect();

        for (left_id, right_id) in outdated_documents {
            self.documents.remove(&(left_id, right_id));
            if let Some(neighbors) = self.adjacency.get_mut(&left_id) {
                neighbors.remove(&right_id);
            }
            if let Some(neighbors) = self.adjacency.get_mut(&right_id) {
                neighbors.remove(&left_id);
            }
        }

        // Cleanup adjacency entries for nodes that have no neighbors left
        self.adjacency.retain(|_, neighbors| !neighbors.is_empty());
    }

    fn alloc_id(&mut self, fp: &RelayFingerprint) -> u64 {
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

    fn id(&self, fp: RelayFingerprint) -> Option<u64> {
        self.fp_to_id.get(&fp).copied()
    }

    fn verify_adjacency(&self, adj: &AdjacencyDescriptor) -> Result<(), AdjacencyError> {
        if adj.left >= adj.right {
            return Err(AdjacencyError::LeftNotSmallerThanRight);
        }

        let left_idpk = if let Some(left) = self.identity(adj.left) {
            left.identity_pk
        } else {
            return Err(AdjacencyError::LeftIdentityNotFound);
        };

        let right_idpk = if let Some(right) = self.identity(adj.right) {
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
    pub left: RelayFingerprint,
    pub right: RelayFingerprint,

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

/// Builder for [`IdentityDescriptor`].
///
/// Typical use:
/// ```rust
/// let descr = IdentityDescriptorBuilder::new(&my_id_secret, &my_onion_secret)
///     .build();
/// ```
pub struct IdentityDescriptorBuilder<'a> {
    identity_secret: &'a RelayIdentitySecret,
    onion_secret: &'a DhSecret,
    unix_timestamp: u64,
    metadata: BTreeMap<String, Bytes>,
}

impl<'a> IdentityDescriptorBuilder<'a> {
    /// Start a new builder using your secrets; the public keys are derived automatically.
    pub fn new(identity_secret: &'a RelayIdentitySecret, onion_secret: &'a DhSecret) -> Self {
        Self {
            identity_secret,
            onion_secret,
            unix_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            metadata: BTreeMap::new(),
        }
    }

    /// Override the timestamp if you need to back-date or pre-date the descriptor.
    #[must_use]
    pub fn unix_timestamp(mut self, ts: u64) -> Self {
        self.unix_timestamp = ts;
        self
    }

    /// Add a single key/value pair to the `metadata` map.
    #[must_use]
    pub fn add_metadata<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<Bytes>,
    {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Add a bunch fo metadata pairs.
    #[must_use]
    pub fn add_metadata_multi<K, V>(mut self, kvv: impl IntoIterator<Item = (K, V)>) -> Self
    where
        K: Into<String>,
        V: Into<Bytes>,
    {
        for (k, v) in kvv {
            self.metadata.insert(k.into(), v.into());
        }
        self
    }

    /// Consume the builder and return a signed `IdentityDescriptor`.
    pub fn build(self) -> IdentityDescriptor {
        // Assemble the unsigned descriptor first…
        let mut descr = IdentityDescriptor {
            identity_pk: self.identity_secret.public(),
            onion_pk: self.onion_secret.public(),
            sig: Bytes::new(),
            unix_timestamp: self.unix_timestamp,
            metadata: self.metadata,
        };

        // …then compute and fill in the signature.
        descr.sig = self.identity_secret.sign(descr.to_sign().as_bytes());

        descr
    }
}

/// An identity descriptor, signed by the owner of an identity. Declares that the identity owns a particular onion key, as well as implicitly
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityDescriptor {
    pub identity_pk: RelayIdentityPublic,
    pub onion_pk: DhPublic,

    pub sig: Bytes,

    pub unix_timestamp: u64,

    pub metadata: BTreeMap<String, Bytes>,
}

impl IdentityDescriptor {
    /// The value that the signatures are supposed to be computed against.
    pub fn to_sign(&self) -> blake3::Hash {
        let mut this = self.clone();
        this.sig = Bytes::new();
        blake3::keyed_hash(b"identity_descriptor_____________", &this.stdcode())
    }

    /// Verifies the signature of the IdentityDescriptor
    pub fn verify(&self) -> Result<(), VerifyError> {
        self.identity_pk
            .verify(self.to_sign().as_bytes(), &self.sig)
    }
}

#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("Invalid signature")]
    InvalidSignature,
}

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct ExitRegistry {
    port_to_exits: BTreeMap<u16, Vec<RelayFingerprint>>,
    exit_configs: HashMap<RelayFingerprint, ExitInfo>,
}

impl ExitRegistry {
    pub fn new() -> Self {
        ExitRegistry {
            port_to_exits: BTreeMap::new(),
            exit_configs: HashMap::new(),
        }
    }

    pub fn add_exit(&mut self, fingerprint: RelayFingerprint, exit_info: ExitInfo) {
        for port in &exit_info.config.allowed_ports {
            self.port_to_exits
                .entry(*port)
                .or_default()
                .push(fingerprint);
        }
        self.exit_configs.insert(fingerprint, exit_info);
    }

    pub fn get_exit(&self, relay_fp: &RelayFingerprint) -> Option<&ExitInfo> {
        self.exit_configs.get(relay_fp)
    }

    pub fn get_random_exit_for_port(&self, port: u16) -> Option<(&RelayFingerprint, &ExitInfo)> {
        self.port_to_exits.get(&port).and_then(|exits| {
            exits
                .iter()
                .choose(&mut thread_rng())
                .and_then(|fingerprint| {
                    self.exit_configs
                        .get(fingerprint)
                        .map(|exit_info| (fingerprint, exit_info))
                })
        })
    }

    pub fn len(&self) -> usize {
        self.exit_configs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.exit_configs.is_empty()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ExitInfo {
    pub haven_endpoint: HavenEndpoint,
    pub config: ExitConfig,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct ExitConfig {
    #[serde(default)]
    pub allowed_ports: Vec<u16>,
}
