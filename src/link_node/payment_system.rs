use std::collections::HashMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::types::NeighborId;

pub struct PaymentSystemSelector {
    inner: HashMap<String, Box<dyn PaymentSystem>>,
}

impl PaymentSystemSelector {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    pub fn get(&self, payment_system: &str) -> Option<&Box<dyn PaymentSystem>> {
        self.inner.get(payment_system)
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

    pub fn select(
        &self,
        name_addrs: &[(String, String)],
    ) -> Option<(&Box<dyn PaymentSystem>, String)> {
        for (name, addr) in name_addrs {
            if let Some(ret) = self.get(name) {
                return Some((ret, addr.to_string()));
            }
        }
        None
    }
}

#[async_trait]
pub trait PaymentSystem: Send + Sync + 'static {
    /// `amount` is in micromel. Returns proof of payment
    async fn pay(&self, my_id: NeighborId, to: &str, amount: u64) -> anyhow::Result<String>;

    async fn verify_payment(
        &self,
        from: NeighborId,
        amount: u64,
        proof: &str,
    ) -> anyhow::Result<bool>;

    fn my_addr(&self) -> String;

    fn name(&self) -> String;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PaymentSystemKind {
    Dummy,
    // OnChain,
    // PoW,
    // Astrape,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SupportedPaymentSystems {
    pub dummy: Option<()>,
}

impl SupportedPaymentSystems {
    pub fn get_available(&self) -> Vec<PaymentSystemKind> {
        let mut available = vec![];
        if self.dummy.is_some() {
            available.push(PaymentSystemKind::Dummy);
        }
        available
    }
}

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
    async fn pay(&self, my_id: NeighborId, to: &str, amount: u64) -> anyhow::Result<String> {
        Ok(format!("{:?},{to},{amount}", my_id))
    }

    async fn verify_payment(
        &self,
        from: NeighborId,
        amount: u64,
        proof: &str,
    ) -> anyhow::Result<bool> {
        Ok(proof == format!("{:?},{},{amount}", from, self.my_addr))
    }

    fn my_addr(&self) -> String {
        self.my_addr.to_string()
    }

    fn name(&self) -> String {
        "dummy".to_string()
    }
}
