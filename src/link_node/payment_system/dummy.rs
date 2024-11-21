use anyhow::Context;
use async_trait::async_trait;
use stdcode::StdcodeSerializeExt;

use super::{PaymentInfo, PaymentProof, PaymentSystem};

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
    async fn new_payment(&self, info: PaymentInfo) -> anyhow::Result<PaymentProof> {
        Ok(PaymentProof(info.stdcode().into()))
    }

    async fn verify_proof(&self, proof: PaymentProof) -> anyhow::Result<PaymentInfo> {
        stdcode::deserialize(&proof.0).context("invalid proof")
    }

    fn my_addr(&self) -> String {
        self.my_addr.to_string()
    }

    fn protocol_name(&self) -> String {
        "dummy".to_string()
    }
}
