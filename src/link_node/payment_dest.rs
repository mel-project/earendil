use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub type Proof = String;

#[async_trait]
pub trait PaymentDestination {
    /// pays `amount` in micromel
    async fn pay(&self, amount: u64) -> anyhow::Result<Proof>;

    async fn verify_proof(&self, proof: Proof) -> anyhow::Result<bool>;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PaymentMethod {
    Dummy,
    // OnChain,
    // PoW,
    // Astrape,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PaymentMethods {
    pub dummy: Option<String>,
}

impl PaymentMethods {
    pub fn get_available(&self) -> Vec<PaymentMethod> {
        let mut available = vec![];
        if self.dummy.is_some() {
            available.push(PaymentMethod::Dummy);
        }
        available
    }
}

pub struct DummyPayDest {
    pub secret: String,
}

#[async_trait]
impl PaymentDestination for DummyPayDest {
    async fn pay(&self, amount: u64) -> anyhow::Result<Proof> {
        Ok(self.secret.clone())
    }

    async fn verify_proof(&self, proof: Proof) -> anyhow::Result<bool> {
        Ok(self.secret == proof)
    }
}
