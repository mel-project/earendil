
use async_trait::async_trait;

use crate::NeighborId;

use super::PaymentSystem;

#[derive(Clone)]
pub struct Dummy {
    my_addr: u64,
}

impl Dummy {
    pub fn new() -> Self {
        Self {
            my_addr: rand::random(),
        }
    }
}

impl Default for Dummy {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PaymentSystem for Dummy {
    async fn pay(
        &self,
        my_id: NeighborId,
        to: &str,
        amount: u64,
        payment_id: &str,
    ) -> anyhow::Result<String> {
        let proof =
            serde_json::to_string(&(format!("{my_id},{to},{amount}"), payment_id.to_string()))?;
        // smol::Timer::after(Duration::from_secs(100)).await;
        Ok(proof)
    }

    async fn verify_payment(
        &self,
        from: NeighborId,
        amount: u64,
        proof: &str,
    ) -> anyhow::Result<Option<String>> {
        let (proof, payment_id): (String, String) = serde_json::from_str(proof)?;
        if proof == format!("{from},{},{amount}", self.my_addr) {
            Ok(Some(payment_id))
        } else {
            Ok(None)
        }
    }

    fn my_addr(&self) -> String {
        self.my_addr.to_string()
    }

    fn name(&self) -> String {
        "dummy".to_string()
    }

    fn max_granularity(&self) -> u64 {
        u64::MAX
    }
}
