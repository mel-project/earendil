use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use blake3::Hash;
use bytes::Bytes;
use dashmap::DashMap;
use earendil_crypt::{Fingerprint, IdentityPublic, IdentitySecret};
use serde::{Deserialize, Serialize};
use smol::channel::{Receiver, Sender};
use stdcode::StdcodeSerializeExt;

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct SettlementRequest {
    // unix milliseconds
    timestamp_ms: u64,
    pub decrease: u128,
    payment_proof: SettlementProof,
    signature: Bytes,
    neighbor_pk: Arc<IdentityPublic>,
}

impl SettlementRequest {
    pub fn new(
        my_sk: IdentitySecret,
        decrease: u128,
        payment_proof: SettlementProof,
        neighbor_pk: Arc<IdentityPublic>,
    ) -> Self {
        let mut request = Self {
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            decrease,
            payment_proof,
            signature: Bytes::new(),
            neighbor_pk,
        };
        let signature = my_sk.sign(request.to_sign().as_bytes());

        request.signature = signature;

        request
    }

    pub fn to_sign(&self) -> Hash {
        let mut this = self.clone();
        this.signature = Bytes::new();

        blake3::keyed_hash(b"settlement-request--------------", &this.stdcode())
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub enum SettlementProof {
    Manual,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SettlementResponse {
    request: SettlementRequest,
    current_debt: i128,
    signature: Bytes,
}

impl SettlementResponse {
    pub fn new(my_sk: IdentitySecret, request: SettlementRequest, current_debt: i128) -> Self {
        let mut response = Self {
            request,
            current_debt,
            signature: Bytes::new(),
        };
        let signature = my_sk.sign(response.to_sign().as_bytes());

        response.signature = signature;

        response
    }

    pub fn to_sign(&self) -> Hash {
        let mut this = self.clone();
        this.signature = Bytes::new();

        blake3::keyed_hash(b"settlement-response-------------", &this.stdcode())
    }
}

pub struct Settlements {
    pending: DashMap<Fingerprint, PendingSettlement>,
}

struct PendingSettlement {
    request: SettlementRequest,
    send_res: Sender<Option<SettlementResponse>>,
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
    ) -> anyhow::Result<Receiver<Option<SettlementResponse>>> {
        let neighbor_pk = request.clone().neighbor_pk;
        neighbor_pk.verify(request.to_sign().as_bytes(), &request.signature)?;

        let (send_res, recv_res) = smol::channel::bounded(1);
        let pending_settlement = PendingSettlement { request, send_res };

        self.pending
            .insert(neighbor_pk.fingerprint(), pending_settlement);

        Ok(recv_res)
    }

    pub async fn send_response(&self, response: Option<SettlementResponse>) -> anyhow::Result<()> {
        if let Some(res) = response {
            let neighbor = res.request.neighbor_pk.fingerprint();
            let settlement = self.pending.get(&neighbor);

            if let Some(settlement) = settlement {
                settlement.send_res.send(Some(res)).await?;
                self.pending.remove(&neighbor);
            }
        }

        Ok(())
    }

    pub fn get_request(&self, neighbor: &Fingerprint) -> Option<SettlementRequest> {
        self.pending.get(neighbor).map(|e| e.request.clone())
    }
}
