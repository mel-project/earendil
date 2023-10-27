use async_trait::async_trait;
use bytes::Bytes;
use nanorpc::nanorpc_derive;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    global_rpc_client::GLOBAL_RPC_DOCK,
    socket::{Endpoint, Socket},
    DaemonContext,
};

#[nanorpc_derive]
#[async_trait]
pub trait GlobalRpcProtocol {
    async fn ping(&self, endpoint: Endpoint, ping_value: Bytes) -> Result<(), PingError>;
}

#[derive(Error, Serialize, Deserialize, Debug)]
pub enum PingError {
    #[error("unable to ping")]
    Ping,
}

pub struct GlobalRpcImpl {
    ctx: DaemonContext,
}

#[async_trait]
impl GlobalRpcProtocol for GlobalRpcImpl {
    async fn ping(&self, endpoint: Endpoint, ping_value: Bytes) -> Result<(), PingError> {
        let socket = Socket::bind(self.ctx.clone(), None, Some(GLOBAL_RPC_DOCK));
        socket
            .send_to(ping_value, endpoint)
            .await
            .map_err(|_| PingError::Ping)?;

        Ok(())
    }
}
