use std::time::{Duration, Instant};

use async_trait::async_trait;
use earendil_crypt::{RelayEndpoint, RelayFingerprint};
use futures_util::{FutureExt, future};
use nanorpc::{JrpcRequest, JrpcResponse, RpcTransport};
use smol::Timer;

use crate::n2r_node::N2rAnonSocket;

use super::GLOBAL_RPC_DOCK;

pub struct GlobalRpcTransport {
    dest_fp: RelayFingerprint,
    skt: N2rAnonSocket,
}

impl GlobalRpcTransport {
    pub fn new(dest_fp: RelayFingerprint, skt: N2rAnonSocket) -> GlobalRpcTransport {
        GlobalRpcTransport { dest_fp, skt }
    }
}

#[async_trait]
impl RpcTransport for GlobalRpcTransport {
    type Error = anyhow::Error;

    async fn call_raw(&self, req: JrpcRequest) -> Result<JrpcResponse, Self::Error> {
        let endpoint = RelayEndpoint::new(self.dest_fp, GLOBAL_RPC_DOCK);
        let mut retries = 0;
        let mut timeout: Duration;
        loop {
            match self
                .skt
                .send_to(serde_json::to_string(&req)?.into(), endpoint)
                .await
            {
                Ok(_) => {}
                Err(e) => tracing::error!("[global_rpc]: error sending message: {}", e),
            }
            tracing::debug!(
                "=====> x{retries} {}/{} ({:?})",
                self.dest_fp,
                req.method,
                req.id
            );

            timeout = Duration::from_secs(2u64.pow(retries + 1));
            let when = Instant::now() + timeout;
            let timer = Timer::at(when);
            let recv_future = Box::pin(self.skt.recv_from());

            match future::select(recv_future, timer.fuse()).await {
                future::Either::Left((res, _)) => match res {
                    Ok((res, _endpoint)) => {
                        let jrpc_res: JrpcResponse =
                            serde_json::from_str(&String::from_utf8(res.to_vec())?)?;
                        tracing::debug!("<===== {}/{} ({:?})", self.dest_fp, req.method, req.id);
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
