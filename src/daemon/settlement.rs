use bytes::Bytes;
use dashmap::DashMap;
use earendil_crypt::Fingerprint;
use serde::{Deserialize, Serialize};
use smol::channel::Sender;

#[derive(Serialize, Deserialize)]
pub struct SettlementRequest {
    // unix milliseconds
    timestamp_ms: u64,
    decrease: u128,
    payment_proof: Bytes,
    signature: Bytes,
    fingerprint: Fingerprint,
}

#[derive(Serialize, Deserialize)]
pub struct SettlementResponse {
    request: SettlementRequest,
    current_debt: u128,
    signature: Bytes,
}

pub struct Settlements {
    pending: DashMap<Fingerprint, PendingSettlement>,
}

struct PendingSettlement {
    req: SettlementRequest,
    sender: oneshot::Sender<SettlementResponse>,
}

impl Default for Settlements {
    fn default() -> Self {
        Self {
            pending: DashMap::new(),
        }
    }
}
