use async_trait::async_trait;
use nanorpc::nanorpc_derive;

use super::DaemonContext;

#[nanorpc_derive]
#[async_trait]
pub trait GlobalRpcProtocol {
    async fn ping(&self, i: u64) -> u64;
}

pub struct GlobalRpcImpl {
    ctx: DaemonContext,
}

impl GlobalRpcImpl {
    pub fn new(ctx: DaemonContext) -> GlobalRpcImpl {
        GlobalRpcImpl { ctx }
    }
}

#[async_trait]
impl GlobalRpcProtocol for GlobalRpcImpl {
    async fn ping(&self, i: u64) -> u64 {
        i
    }
}
