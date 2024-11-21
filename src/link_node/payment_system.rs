mod dummy;

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

pub use dummy::Dummy;

#[async_trait]
/// A trait that all payment systems implement. A payment system can be understood a
pub trait PaymentSystem: Send + Sync + 'static {
    async fn new_payment(&self, info: PaymentInfo) -> anyhow::Result<PaymentProof>;
    async fn verify_proof(&self, proof: PaymentProof) -> anyhow::Result<PaymentInfo>;

    fn my_addr(&self) -> String;
    fn protocol_name(&self) -> String;
}

/// The proof that a payment happened. This is an opaque bytestring that must be encoded and decoded by system-specific code, and which must carry enough information to verify the payment and reconstruct the original PaymentInfo.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PaymentProof(pub Bytes);

/// The information needed to create a new payment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentInfo {
    pub dst_addr: String,
    pub src_addr: String,
    pub amount_micromel: u64,
    pub nonce: u64,
}
