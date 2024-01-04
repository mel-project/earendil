use bytes::Bytes;
use concurrent_queue::ConcurrentQueue;
use dashmap::DashMap;
use earendil_crypt::Fingerprint;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, PartialEq)]
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
    pending: DashMap<Fingerprint, ConcurrentQueue<PendingSettlement>>,
}

struct PendingSettlement {
    request: SettlementRequest,
    send_res: oneshot::Sender<SettlementResponse>,
}

impl Default for Settlements {
    fn default() -> Self {
        Self {
            pending: DashMap::new(),
        }
    }
}

impl Settlements {
    pub fn insert_pending(
        &self,
        request: SettlementRequest,
    ) -> anyhow::Result<oneshot::Receiver<SettlementResponse>> {
        let neighbor = request.fingerprint;
        let (send_res, recv_res) = oneshot::channel();
        let pending_settlement = PendingSettlement { request, send_res };

        let entry = self
            .pending
            .entry(neighbor)
            .or_insert(ConcurrentQueue::unbounded());

        match entry.push(pending_settlement) {
            Ok(_) => Ok(recv_res),
            Err(e) => Err(anyhow::anyhow!("{e}")),
        }
    }

    pub fn remove_pending(&self, request: SettlementRequest) -> anyhow::Result<()> {
        let neighbor = request.fingerprint;

        if let Some(queue) = self.pending.get_mut(&neighbor) {
            let mut temp_queue = vec![];

            while let Ok(pending) = queue.pop() {
                if pending.request != request {
                    temp_queue.push(pending);
                }
            }

            for item in temp_queue {
                let _ = queue.push(item);
            }
        }

        Ok(())
    }
}
