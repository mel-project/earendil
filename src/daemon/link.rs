use std::{ops::DerefMut, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use earendil_crypt::RelayFingerprint;
use futures::{
    io::{ReadHalf, WriteHalf},
    AsyncBufReadExt,
};
use futures_util::io::AsyncReadExt;
use nanorpc::{DynRpcTransport, JrpcRequest, JrpcResponse, RpcService, RpcTransport};
use nursery_macro::nursery;
use picomux::{PicoMux, Stream};
use serde::{Deserialize, Serialize};
use smol::io::{AsyncWriteExt, BufReader};
use stdcode::StdcodeSerializeExt;

use crate::pascal::{read_pascal, write_pascal};

const LABEL_RPC: &[u8] = b"!rpc";

/// Link represents a link to a neighbor, either client or relay.
///
/// This presents a self-contained abstraction that does not depend on anything "global" in the context
pub struct Link {
    mux: Arc<PicoMux>,
    read: smol::lock::Mutex<ReadHalf<picomux::Stream>>,
    write: smol::lock::Mutex<WriteHalf<picomux::Stream>>,
}

impl Link {
    /// Constructs a link, given a picomux multiplex. We initialize the message stream.
    pub async fn new_dial(mux: PicoMux) -> anyhow::Result<Self> {
        let msg_stream = mux.open(b"").await?;
        let (read, write) = msg_stream.split();
        Ok(Link {
            mux: mux.into(),
            read: read.into(),
            write: write.into(),
        })
    }

    /// Constructs a link, given a picomux multiplex. The other side initializes the message stream.
    pub async fn new_listen(mux: PicoMux) -> anyhow::Result<Self> {
        let msg_stream = mux.accept().await?;
        let (read, write) = msg_stream.split();
        Ok(Link {
            mux: mux.into(),
            read: read.into(),
            write: write.into(),
        })
    }

    pub async fn send_msg(&self, msg: LinkMessage) -> anyhow::Result<()> {
        let mut write = self.write.lock().await;
        write_pascal(&msg.stdcode(), write.deref_mut()).await?;
        Ok(())
    }

    pub async fn recv_msg(&self) -> anyhow::Result<LinkMessage> {
        let mut read = self.read.lock().await;
        let bts = read_pascal(read.deref_mut()).await?;
        Ok(stdcode::deserialize(&bts)?)
    }

    pub fn rpc_transport(&self) -> DynRpcTransport {
        DynRpcTransport::new(MuxRpcTransport {
            mux: self.mux.clone(),
        })
    }

    pub async fn rpc_serve(&self, service: impl RpcService) -> anyhow::Result<()> {
        nursery!({
            loop {
                let stream = self.mux.accept().await?;
                if stream.metadata() == LABEL_RPC {
                    spawn!(async {
                        let (read, mut write) = stream.split();
                        let mut read = BufReader::new(read);
                        for _ in 0..1000 {
                            let mut line = String::new();
                            read.read_line(&mut line).await?;
                            let req: JrpcRequest = serde_json::from_str(&line)?;
                            let resp = service.respond_raw(req).await;
                            write
                                .write_all(
                                    format!("{}\n", serde_json::to_string(&resp)?).as_bytes(),
                                )
                                .await?;
                        }
                        anyhow::Ok(())
                    })
                    .detach();
                }
            }
        })
    }
}

struct MuxRpcTransport {
    mux: Arc<PicoMux>,
}

#[async_trait]
impl RpcTransport for MuxRpcTransport {
    type Error = anyhow::Error;

    async fn call_raw(&self, req: JrpcRequest) -> Result<JrpcResponse, Self::Error> {
        let mut conn = self.mux.open(LABEL_RPC).await?;
        conn.write_all(format!("{}\n", serde_json::to_string(&req)?).as_bytes())
            .await?;
        let mut conn = BufReader::new(conn);
        let mut line = String::new();
        conn.read_line(&mut line).await?;
        let response: JrpcResponse = serde_json::from_str(&line)?;
        Ok(response)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum LinkMessage {
    ToRelay {
        packet: Bytes,
        next_peeler: RelayFingerprint,
    },
    ToClient {
        body: Bytes,
        rb_id: u64,
    },
}
