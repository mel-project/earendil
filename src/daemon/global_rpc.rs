use async_trait::async_trait;
use earendil_crypt::Fingerprint;
use earendil_packet::Dock;
use nanorpc::{JrpcRequest, JrpcResponse, RpcTransport};

use crate::daemon::socket::Endpoint;

use super::{socket::Socket, DaemonContext};

pub const GLOBAL_RPC_DOCK: Dock = 100001;

struct GlobalRpcClient {
    ctx: DaemonContext,
    dest: Fingerprint,
}

impl GlobalRpcClient {
    pub fn new(ctx: DaemonContext, dest: Fingerprint) -> GlobalRpcClient {
        GlobalRpcClient { ctx, dest }
    }
}

#[async_trait]
impl RpcTransport for GlobalRpcClient {
    type Error = anyhow::Error;

    async fn call_raw(&self, req: JrpcRequest) -> Result<JrpcResponse, Self::Error> {
        let endpoint = Endpoint::new(self.dest, GLOBAL_RPC_DOCK);
        let socket = Socket::bind(self.ctx.clone(), None, None);
        socket
            .send_to(serde_json::to_string(&req)?.into(), endpoint)
            .await?;
        let res = socket.recv_from().await?;
        let jrpc_res: JrpcResponse = stdcode::deserialize(&res.0)?;

        Ok(jrpc_res)
    }
}
