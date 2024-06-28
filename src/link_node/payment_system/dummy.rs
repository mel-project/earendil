use std::time::Duration;

use async_trait::async_trait;

use crate::NodeId;

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

#[async_trait]
impl PaymentSystem for Dummy {
    async fn pay(
        &self,
        my_id: NodeId,
        to: &str,
        amount: u64,
        payment_id: &str,
    ) -> anyhow::Result<String> {
        let proof =
            serde_json::to_string(&(format!("{my_id},{to},{amount}"), payment_id.to_string()))?;
        smol::Timer::after(Duration::from_secs(1)).await;
        Ok(proof)
    }

    async fn verify_payment(
        &self,
        from: NodeId,
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
}
