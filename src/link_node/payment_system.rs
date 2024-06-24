use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::types::NodeId;

pub struct PaymentSystemSelector {
    inner: HashMap<String, Arc<Box<dyn PaymentSystem>>>,
}

impl PaymentSystemSelector {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    pub fn get(&self, payment_system: &str) -> Option<&Arc<Box<dyn PaymentSystem>>> {
        self.inner.get(payment_system)
    }

    pub fn insert(&mut self, payment_system: Box<dyn PaymentSystem>) {
        self.inner
            .insert(payment_system.name(), Arc::new(payment_system));
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
    ) -> Option<(Arc<Box<dyn PaymentSystem>>, String)> {
        for (name, addr) in name_addrs {
            if let Some(ret) = self.get(name) {
                return Some((ret.clone(), addr.to_string()));
            }
        }
        None
    }
}

#[async_trait]
pub trait PaymentSystem: Send + Sync + 'static {
    /// `amount` is in micromel. Returns proof of payment
    async fn pay(
        &self,
        my_id: NodeId,
        to: &str,
        amount: u64,
        payment_id: &str,
    ) -> anyhow::Result<String>;

    /// returns Some(payment_id) if payment is valid, None otherwise
    async fn verify_payment(
        &self,
        from: NodeId,
        amount: u64,
        proof: &str,
    ) -> anyhow::Result<Option<String>>;

    fn my_addr(&self) -> String;

    fn name(&self) -> String;

    fn clone_box(&self) -> Box<dyn PaymentSystem>;
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
    async fn pay(
        &self,
        my_id: NodeId,
        to: &str,
        amount: u64,
        payment_id: &str,
    ) -> anyhow::Result<String> {
        let proof =
            serde_json::to_string(&(format!("{my_id},{to},{amount}"), payment_id.to_string()))?;
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

    fn clone_box(&self) -> Box<dyn PaymentSystem> {
        Box::new(self.clone())
    }
}

#[derive(Clone)]
pub struct PoW;

#[async_trait]
impl PaymentSystem for PoW {
    async fn pay(&self, my_id: NodeId, to: &str, amount: u64, ott: &str) -> anyhow::Result<String> {
        // return (ott, difficulty, proof).serialize() as proof
        todo!()
    }

    async fn verify_payment(
        &self,
        from: NodeId,
        amount: u64,
        proof: &str,
    ) -> anyhow::Result<Option<String>> {
        // deserialize proof
        // verify proof with melpow & return payment_id
        todo!()
    }

    fn my_addr(&self) -> String {
        String::new()
    }

    fn name(&self) -> String {
        "pow".to_string()
    }

    fn clone_box(&self) -> Box<dyn PaymentSystem> {
        Box::new(self.clone())
    }
}
