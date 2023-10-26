use std::time::{Duration, Instant};

use async_trait::async_trait;
use earendil_crypt::Fingerprint;
use earendil_packet::Dock;
use futures_util::{future, FutureExt};
use nanorpc::{JrpcRequest, JrpcResponse, RpcTransport};
use smol::{lock::futures, Timer};

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

        let mut retries = 0;
        let max_retries = 3;
        let mut timeout: Duration;

        while retries <= max_retries {
            socket
                .send_to(serde_json::to_string(&req)?.into(), endpoint.clone())
                .await?;

            timeout = Duration::from_secs(2u64.pow(retries));
            let when = Instant::now() + timeout;
            let timer = Timer::at(when);
            let recv_future = Box::pin(socket.recv_from());

            match future::select(recv_future, timer.fuse()).await {
                future::Either::Left((res, _)) => match res {
                    Ok(res) => {
                        let jrpc_res: JrpcResponse = stdcode::deserialize(&res.0)?;
                        return Ok(jrpc_res);
                    }
                    Err(_) => {
                        return Err(anyhow::anyhow!("error receiving GlobalRPC response"));
                    }
                },
                future::Either::Right((_, _)) => {
                    retries += 1;
                    continue;
                }
            }
        }

        Err(anyhow::anyhow!(format!(
            "all retransmission attempts failed for {}",
            serde_json::to_string_pretty(&req)?
        )))
    }
}
