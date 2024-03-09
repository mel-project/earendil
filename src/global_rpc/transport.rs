use std::time::{Duration, Instant};

use async_trait::async_trait;
use earendil_crypt::RelayFingerprint;
use futures_util::{future, FutureExt};
use nanorpc::{JrpcRequest, JrpcResponse, RpcTransport};
use smol::Timer;

use crate::{
    daemon::context::DaemonContext,
    socket::{n2r_socket::N2rClientSocket, RelayEndpoint},
};

use super::GLOBAL_RPC_DOCK;

pub struct GlobalRpcTransport {
    ctx: DaemonContext,
    dest_fp: RelayFingerprint,
}

impl GlobalRpcTransport {
    pub fn new(ctx: DaemonContext, dest_fp: RelayFingerprint) -> GlobalRpcTransport {
        GlobalRpcTransport { ctx, dest_fp }
    }
}

#[async_trait]
impl RpcTransport for GlobalRpcTransport {
    type Error = anyhow::Error;

    async fn call_raw(&self, req: JrpcRequest) -> Result<JrpcResponse, Self::Error> {
        let endpoint = RelayEndpoint::new(self.dest_fp, GLOBAL_RPC_DOCK);
        let socket = N2rClientSocket::bind(self.ctx.clone(), None);
        let mut retries = 0;
        let mut timeout: Duration;

        loop {
            socket.send_to(serde_json::to_string(&req)?.into(), endpoint)?;
            // tracing::debug!(
            //     "=====> x{retries} {}/{} ({:?})",
            //     self.dest_fp,
            //     req.method,
            //     req.id
            // );

            timeout = Duration::from_secs(2u64.pow(retries + 1));
            let when = Instant::now() + timeout;
            let timer = Timer::at(when);
            let recv_future = Box::pin(socket.recv_from());

            match future::select(recv_future, timer.fuse()).await {
                future::Either::Left((res, _)) => match res {
                    Ok((res, _endpoint)) => {
                        let jrpc_res: JrpcResponse =
                            serde_json::from_str(&String::from_utf8(res.to_vec())?)?;
                        // tracing::debug!("<===== {}/{} ({:?})", self.dest_fp, req.method, req.id);
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
    }
}
