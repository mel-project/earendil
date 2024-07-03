use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use melpow::{HashFunction, SVec};
use stdcode::StdcodeSerializeExt;

use crate::NodeId;

use super::PaymentSystem;

pub struct BigHasher;

impl HashFunction for BigHasher {
    fn hash(&self, b: &[u8], k: &[u8]) -> SVec<u8> {
        let mut res = blake3::keyed_hash(blake3::hash(k).as_bytes(), b);
        for _ in 0..99 {
            res = blake3::hash(res.as_bytes());
        }
        SVec::from_slice(res.as_bytes())
    }
}

pub struct PoW {
    mel_client: Arc<melprot::Client>,
}

impl PoW {
    pub fn new(mel_client: Arc<melprot::Client>) -> Self {
        Self { mel_client }
    }
}

#[async_trait]
impl PaymentSystem for PoW {
    async fn pay(
        &self,
        my_id: NodeId,
        _to: &str,
        amount: u64,
        payment_id: &str,
    ) -> anyhow::Result<String> {
        let puzzle = (payment_id.to_string(), my_id).stdcode();
        // get difficulty ~ equivalent to 10x amount in mel
        let dosc_speed = self
            .mel_client
            .latest_snapshot()
            .await?
            .current_header()
            .dosc_speed;
        let difficulty = micromel_to_difficulty(5 * amount, dosc_speed);
        tracing::debug!(
            "PoW.pay() with difficulty = {difficulty}, equivalent to {} mel",
            difficulty_to_micromel(difficulty, dosc_speed) as f64 / 1_000_000.0
        );
        let proof = melpow::Proof::generate(&puzzle, difficulty as _, BigHasher).to_bytes();
        tracing::debug!("generated PoW proof!");
        let ret = serde_json::to_string(&(puzzle, difficulty, proof))?;
        Ok(ret)
    }

    async fn verify_payment(
        &self,
        from: NodeId,
        amount: u64,
        proof: &str,
    ) -> anyhow::Result<Option<String>> {
        let (puzzle, difficulty, proof): (Vec<u8>, u32, Vec<u8>) = serde_json::from_str(proof)?;
        let proof =
            melpow::Proof::from_bytes(&proof).context("unable to deserialize melpow proof")?;
        let micromel = difficulty_to_micromel(
            difficulty,
            self.mel_client
                .latest_snapshot()
                .await?
                .current_header()
                .dosc_speed,
        );
        println!("MICROMEL from DIFFICULTY = {micromel}");
        if proof.verify(&puzzle, difficulty as _, BigHasher) && micromel > 4 * amount {
            let (payment_id, sender_id): (String, NodeId) = stdcode::deserialize(&puzzle)?;
            if sender_id == from {
                return Ok(Some(payment_id));
            }
        };
        println!("verify proof FAILED! difficulty = {difficulty}");
        Ok(None)
    }

    fn my_addr(&self) -> String {
        String::new()
    }

    fn name(&self) -> String {
        "pow".to_string()
    }

    fn max_granularity(&self) -> u64 {
        10
    }
}

fn micromel_to_difficulty(micromel: u64, dosc_speed: u128) -> u32 {
    // assuming melmint is functioning correctly, amount in mel = amount in dosc.
    // to calculate the difficulty needed to produce this much mel via running melmint on the client's computer, we would need to measure the client's cpu speed.
    // because that is hasslesome, we assume the client has the fastest computer on the network.
    // 1 dosc = latest_snapshot().dosc_speed * 86400 / 30 # of hashes. dosc speed is #hashes/block. 1 block/30s

    let bighashes_per_mel = dosc_speed as f64 * 86400.0 / 30.0 / 100.0; // 100-fold nested hashes
    let amt_mel = micromel as f64 / 1_000_000.0;
    let num_hashes = amt_mel * bighashes_per_mel;
    // println!("micromel = {micromel}, dosc_speed = {dosc_speed}, num_hashes = {num_hashes}");
    num_hashes.log2().ceil() as u32
}

fn difficulty_to_micromel(difficulty: u32, dosc_speed: u128) -> u64 {
    let num_bighashes = 2.0_f64.powi(difficulty as i32);
    let bighashes_per_mel = dosc_speed as f64 * 86400.0 / 30.0 / 100.0;
    let amt_mel = num_bighashes / bighashes_per_mel;
    (1_000_000.0 * amt_mel) as u64
}
