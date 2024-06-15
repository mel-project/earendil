// use std::{
//     collections::HashSet,
//     fmt,
//     sync::Arc,
//     time::{Duration, SystemTime, UNIX_EPOCH},
// };

// use blake3::Hash;
// use bytes::Bytes;
// use dashmap::DashMap;
// use earendil_crypt::{RelayFingerprint, RelayIdentityPublic, RelayIdentitySecret};
// use melpow::{HashFunction, SVec};
// use moka::sync::{Cache, CacheBuilder};
// use serde::{Deserialize, Serialize};
// use smol::channel::{Receiver, Sender};
// use stdcode::StdcodeSerializeExt;

// use crate::config::AutoSettle;

// pub struct Hasher;

// impl HashFunction for Hasher {
//     fn hash(&self, b: &[u8], k: &[u8]) -> SVec<u8> {
//         let mut res = blake3::keyed_hash(blake3::hash(k).as_bytes(), b);
//         for _ in 0..100 {
//             res = blake3::hash(res.as_bytes());
//         }
//         SVec::from_slice(res.as_bytes())
//     }
// }

// // a stand in for the real Mel getter
// pub fn onchain_multiplier() -> u64 {
//     1
// }

// pub fn difficulty_to_micromel(difficulty: usize) -> u64 {
//     let work = (2u64).pow(difficulty as u32);
//     work.saturating_mul(onchain_multiplier())
// }

// #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
// pub struct SettlementRequest {
//     timestamp_ms: u64,
//     decrease: u64,
//     pub payment_proof: SettlementProof,
//     signature: Bytes,
//     initiator_pk: Arc<RelayIdentityPublic>,
// }

// impl fmt::Display for SettlementRequest {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         write!(
//             f, "SettlementRequest {{ timestamp_ms: {}, decrease: {}, payment proof: {:?}, initiator fingerprint: {} }}",
//             self.timestamp_ms,
//             self.decrease,
//             self.payment_proof,
//             self.initiator_pk.fingerprint()
//         )
//     }
// }

// impl SettlementRequest {
//     pub fn new(my_sk: RelayIdentitySecret, decrease: u64, payment_proof: SettlementProof) -> Self {
//         let mut request = Self {
//             timestamp_ms: SystemTime::now()
//                 .duration_since(UNIX_EPOCH)
//                 .unwrap()
//                 .as_secs(),
//             decrease,
//             payment_proof,
//             signature: Bytes::new(),
//             initiator_pk: my_sk.public().into(),
//         };
//         let signature = my_sk.sign(request.to_sign().as_bytes());

//         request.signature = signature.clone();

//         request
//     }

//     pub fn to_sign(&self) -> Hash {
//         let mut this = self.clone();
//         this.signature = Bytes::new();

//         blake3::keyed_hash(b"settlement-request--------------", &this.stdcode())
//     }
// }

// #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
// pub enum SettlementProof {
//     Automatic(AutoSettleProof),
//     Manual,
// }

// impl SettlementProof {
//     pub fn new_auto(seed: Seed, difficulty: usize) -> Self {
//         log::debug!("generating mel PoW with difficulty {difficulty}...");
//         let proof = melpow::Proof::generate(&seed, difficulty, Hasher).to_bytes();
//         SettlementProof::Automatic(AutoSettleProof {
//             seed,
//             difficulty,
//             proof,
//         })
//     }
// }

// pub type Seed = [u8; 32];
// #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
// pub struct AutoSettleProof {
//     pub seed: Seed,
//     pub difficulty: usize,
//     pub proof: Vec<u8>,
// }

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct SettlementResponse {
//     pub request: SettlementRequest,
//     pub current_debt: i128,
//     pub signature: Bytes,
// }

// impl SettlementResponse {
//     pub fn new(my_sk: RelayIdentitySecret, request: SettlementRequest, current_debt: i128) -> Self {
//         let mut response = Self {
//             request,
//             current_debt,
//             signature: Bytes::new(),
//         };
//         let signature = my_sk.sign(response.to_sign().as_bytes());

//         response.signature = signature;

//         response
//     }

//     pub fn to_sign(&self) -> Hash {
//         let mut this = self.clone();
//         this.signature = Bytes::new();

//         blake3::keyed_hash(b"settlement-response-------------", &this.stdcode())
//     }
// }

// pub struct Settlements {
//     pending: DashMap<RelayFingerprint, PendingSettlement>,
//     pub seed_cache: Cache<u64, HashSet<Seed>>,
//     pub auto_settle: Option<AutoSettle>,
// }

// impl Settlements {
//     pub fn new(auto_settle: Option<AutoSettle>) -> Self {
//         Settlements {
//             pending: DashMap::new(),
//             seed_cache: CacheBuilder::default()
//                 .time_to_live(Duration::from_secs(60))
//                 .build(),
//             auto_settle,
//         }
//     }
// }

// #[derive(Debug)]
// struct PendingSettlement {
//     request: SettlementRequest,
//     send_res: Sender<Option<SettlementResponse>>,
// }

// impl Settlements {
//     // handles manual settlements
//     pub fn insert_pending(
//         &self,
//         request: SettlementRequest,
//     ) -> anyhow::Result<Receiver<Option<SettlementResponse>>> {
//         let initiator_pk = request.clone().initiator_pk;
//         initiator_pk.verify(request.to_sign().as_bytes(), &request.signature)?;

//         match request.payment_proof {
//             SettlementProof::Manual => (),
//             _ => return Err(anyhow::anyhow!("expected manual settlement proof")),
//         };

//         let (send_res, recv_res) = smol::channel::bounded(1);
//         let pending_settlement = PendingSettlement {
//             request: request.clone(),
//             send_res,
//         };

//         self.pending
//             .insert(initiator_pk.fingerprint(), pending_settlement);

//         Ok(recv_res)
//     }

//     pub async fn reject_response(&self, neighbor: &RelayFingerprint) -> anyhow::Result<()> {
//         if let Some(settlement) = self.pending.get(neighbor) {
//             settlement.send_res.send(None).await?
//         }

//         self.pending.remove(neighbor);
//         Ok(())
//     }

//     pub fn get_request(&self, neighbor: &RelayFingerprint) -> Option<SettlementRequest> {
//         self.pending.get(neighbor).map(|e| e.request.clone())
//     }

//     pub fn list(&self) -> Vec<String> {
//         self.pending
//             .iter()
//             .map(|entry| entry.request.to_string())
//             .collect()
//     }
// }
