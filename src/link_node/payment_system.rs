mod dummy;
mod onchain;
mod pow;

use std::collections::HashMap;

use anyhow::Context;
use async_trait::async_trait;
use base32::Alphabet;
use serde::{Deserialize, Serialize};
use tmelcrypt::Ed25519SK;

use super::types::NodeId;
pub use dummy::Dummy;
pub use onchain::OnChain;
pub use pow::PoW;

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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PaymentSystemKind {
    Dummy,
    PoW,
    OnChain(Ed25519SK),
    // Astrape,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SupportedPaymentSystems {
    pub dummy: Option<()>,
    pub pow: Option<()>,
    pub onchain: Option<String>,
}

impl SupportedPaymentSystems {
    pub fn get_available(&self) -> anyhow::Result<Vec<PaymentSystemKind>> {
        let mut available = vec![];
        if self.dummy.is_some() {
            available.push(PaymentSystemKind::Dummy);
        }
        if self.pow.is_some() {
            available.push(PaymentSystemKind::PoW);
        }
        if let Some(secret) = &self.onchain {
            let secret = base32::decode(Alphabet::Crockford, &secret)
                .context("Failed to decode secret key")?;
            let sk = ed25519_dalek::SigningKey::from_bytes(secret.as_slice().try_into()?);
            let pk = sk.verifying_key();
            let mut vv = [0u8; 64];
            vv[0..32].copy_from_slice(&sk.to_bytes());
            vv[32..].copy_from_slice(&pk.to_bytes());
            let sk = Ed25519SK::from_bytes(&vv).unwrap();
            available.push(PaymentSystemKind::OnChain(sk))
        }
        Ok(available)
    }
}
