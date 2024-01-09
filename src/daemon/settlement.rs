use std::{
    fmt,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use blake3::Hash;
use bytes::Bytes;
use dashmap::DashMap;
use earendil_crypt::{Fingerprint, IdentityPublic, IdentitySecret};
use serde::{Deserialize, Serialize};
use smol::channel::{Receiver, Sender};
use stdcode::StdcodeSerializeExt;

use super::context::{DaemonContext, DEBTS, GLOBAL_IDENTITY};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SettlementRequest {
    // unix milliseconds
    timestamp_ms: u64,
    pub decrease: u64,
    payment_proof: SettlementProof,
    signature: Bytes,
    initiator_pk: Arc<IdentityPublic>,
}

impl fmt::Display for SettlementRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f, "SettlementRequest {{ timestamp_ms: {}, decrease: {}, payment proof: {:?}, initiator fingerprint: {} }}",
            self.timestamp_ms,
            self.decrease,
            self.payment_proof,
            self.initiator_pk.fingerprint()
        )
    }
}

impl SettlementRequest {
    pub fn new(my_sk: IdentitySecret, decrease: u64, payment_proof: SettlementProof) -> Self {
        let mut request = Self {
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            decrease,
            payment_proof,
            signature: Bytes::new(),
            initiator_pk: my_sk.public().into(),
        };
        let signature = my_sk.sign(request.to_sign().as_bytes());

        request.signature = signature.clone();

        request
    }

    pub fn to_sign(&self) -> Hash {
        let mut this = self.clone();
        this.signature = Bytes::new();

        blake3::keyed_hash(b"settlement-request--------------", &this.stdcode())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum SettlementProof {
    Manual,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementResponse {
    pub request: SettlementRequest,
    pub current_debt: i128,
    pub signature: Bytes,
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

#[derive(Debug)]
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
        let initiator_pk = request.clone().initiator_pk;
        initiator_pk.verify(request.to_sign().as_bytes(), &request.signature)?;

        let (send_res, recv_res) = smol::channel::bounded(1);
        let pending_settlement = PendingSettlement {
            request: request.clone(),
            send_res,
        };

        self.pending
            .insert(initiator_pk.fingerprint(), pending_settlement);

        Ok(recv_res)
    }

    pub async fn accept_response(
        &self,
        ctx: &DaemonContext,
        neighbor: Fingerprint,
        request: SettlementRequest,
    ) -> anyhow::Result<()> {
        let debts = ctx.get(DEBTS);
        let current_debt = debts
            .net_debt_est(&neighbor)
            .context("unable to retrieve net debt")?;
        let deduct_amount = request.decrease;
        let settled_debt = current_debt.saturating_sub(deduct_amount as i128);
        let my_sk = ctx.get(GLOBAL_IDENTITY);
        let response = SettlementResponse::new(*my_sk, request, settled_debt);

        if let Some(settlement) = self.pending.get(&neighbor) {
            settlement.send_res.send(Some(response)).await?;
            debts.deduct_settlement(&neighbor, deduct_amount);
        }

        self.pending.remove(&neighbor);
        Ok(())
    }

    pub async fn reject_response(&self, neighbor: &Fingerprint) -> anyhow::Result<()> {
        if let Some(settlement) = self.pending.get(neighbor) {
            settlement.send_res.send(None).await?
        }

        self.pending.remove(neighbor);
        Ok(())
    }

    pub fn get_request(&self, neighbor: &Fingerprint) -> Option<SettlementRequest> {
        self.pending.get(neighbor).map(|e| e.request.clone())
    }

    pub fn list(&self) -> Vec<String> {
        self.pending
            .iter()
            .map(|entry| entry.request.to_string())
            .collect()
    }
}
