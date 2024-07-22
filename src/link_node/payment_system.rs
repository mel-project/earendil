mod dummy;
mod onchain;
mod pow;

use std::collections::HashMap;

use async_trait::async_trait;

use super::types::NeighborId;
pub use dummy::Dummy;
pub use onchain::OnChain;
pub use pow::PoW;

#[async_trait]
pub trait PaymentSystem: Send + Sync + 'static {
    /// `amount` is in micromel. Returns proof of payment
    async fn pay(
        &self,
        my_id: NeighborId,
        to: &str,
        amount: u64,
        payment_id: &str,
    ) -> anyhow::Result<String>;

    /// returns Some(payment_id) if payment is valid, None otherwise
    async fn verify_payment(
        &self,
        from: NeighborId,
        amount: u64,
        proof: &str,
    ) -> anyhow::Result<Option<String>>;

    fn my_addr(&self) -> String;

    fn name(&self) -> String;

    /// max amount a payment can be, in micromels
    fn max_granularity(&self) -> u64;
}

pub struct PaymentSystemSelector {
    inner: HashMap<String, Box<dyn PaymentSystem>>,
}

impl PaymentSystemSelector {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    pub fn get(&self, payment_system: &str) -> Option<&dyn PaymentSystem> {
        self.inner.get(payment_system).map(|s| s.as_ref())
    }

    pub fn insert(&mut self, payment_system: Box<dyn PaymentSystem>) {
        self.inner.insert(payment_system.name(), payment_system);
    }

    pub fn get_available(&self) -> Vec<(String, String)> {
        self.inner
            .iter()
            .map(|(name, ps)| (name.clone(), ps.my_addr()))
            .collect()
    }

    pub fn select(&self, name_addrs: &[(String, String)]) -> Option<(&dyn PaymentSystem, String)> {
        for (name, addr) in name_addrs {
            if let Some(ret) = self.get(name) {
                return Some((ret, addr.to_string()));
            }
        }
        None
    }
}
