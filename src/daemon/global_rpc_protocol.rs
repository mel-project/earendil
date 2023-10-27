use async_trait::async_trait;
use nanorpc::nanorpc_derive;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::DaemonContext;

#[nanorpc_derive]
#[async_trait]
pub trait GlobalRpcProtocol {
    async fn ping(&self, i: u64) -> u64;
}

pub struct GlobalRpcImpl {
    ctx: DaemonContext,
}

#[async_trait]
impl GlobalRpcProtocol for GlobalRpcImpl {
    async fn ping(&self, i: u64) -> u64 {
        i
    }
}
