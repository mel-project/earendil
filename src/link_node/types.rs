use earendil_crypt::RelayFingerprint;
use serde::{Deserialize, Serialize};

pub type ClientId = u64;

#[derive(Clone, Copy, Eq, PartialEq, Debug, Hash, Serialize, Deserialize)]
pub enum NeighborId {
    Relay(RelayFingerprint),
    Client(ClientId),
}
