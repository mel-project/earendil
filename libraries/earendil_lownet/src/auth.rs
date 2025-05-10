use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
/// TODO signature
pub struct AddrAssignment {
    pub client_id: u64,
    pub unix_secs: u64,
}
