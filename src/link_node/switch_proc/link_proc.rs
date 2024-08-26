use super::{read_pascal, write_pascal, SwitchMessage, SwitchProcess};

use ahash::AHashMap;
use bytes::Bytes;

use earendil_crypt::{ClientId, RelayFingerprint};

use futures_util::io::AsyncReadExt;
use haiyuu::{Handle, WeakHandle};
use nanorpc::{JrpcId, JrpcRequest, JrpcResponse, RpcService};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use smol::future::FutureExt as _;

pub struct LinkProcess {
    switch: WeakHandle<SwitchProcess>,
    remote: either::Either<RelayFingerprint, ClientId>,
    rpc_serve: Option<Box<dyn RpcService>>,
    inflight_rpc: Mutex<AHashMap<JrpcId, oneshot::Sender<JrpcResponse>>>,

    pipe: Box<dyn sillad::Pipe>,
}

impl LinkProcess {
    pub fn new(
        switch: WeakHandle<SwitchProcess>,
        remote: either::Either<RelayFingerprint, ClientId>,
        rpc_serve: Option<impl RpcService>,
        pipe: impl sillad::Pipe,
    ) -> Self {
        Self {
            switch,
            remote,
            rpc_serve: rpc_serve.map(|s| {
                let x: Box<dyn RpcService> = Box::new(s);
                x
            }),
            inflight_rpc: Mutex::new(AHashMap::new()),
            pipe: Box::new(pipe),
        }
    }
}

#[derive(Debug)]
pub enum LinkMsg {
    Message(Bytes),
    Request(JrpcRequest, oneshot::Sender<JrpcResponse>),
    Response(JrpcResponse),
}

impl haiyuu::Process for LinkProcess {
    type Message = LinkMsg;
    type Output = ();
    const MAILBOX_CAP: usize = 100;

    async fn run(&mut self, mailbox: &mut haiyuu::Mailbox<Self>) -> Self::Output {
        let (mut read_pipe, mut write_pipe) = (&mut self.pipe).split();
        let self_handle = mailbox.handle();

        let upload_loop = async {
            let mut buf = vec![];
            loop {
                buf.clear();
                let msg = match mailbox.recv().await {
                    LinkMsg::Message(msg) => LinkWireMessage::Message(msg),
                    LinkMsg::Request(req, resp) => {
                        self.inflight_rpc.lock().insert(req.id.clone(), resp);
                        LinkWireMessage::Request(req)
                    }
                    LinkMsg::Response(resp) => LinkWireMessage::Response(resp),
                };
                ciborium::into_writer(&msg, &mut buf)?;
                write_pascal(&buf, &mut write_pipe).await?;
            }
        };

        let download_loop = async {
            loop {
                let msg = read_pascal(&mut read_pipe).await?;
                let msg: LinkWireMessage = ciborium::from_reader(&msg[..])?;
                match msg {
                    LinkWireMessage::Message(msg) => match self.remote {
                        either::Either::Left(relay) => {
                            self.switch
                                .send(SwitchMessage::FromRelay(msg, relay))
                                .await?;
                        }
                        either::Either::Right(client) => {
                            self.switch
                                .send(SwitchMessage::FromClient(msg, client))
                                .await?;
                        }
                    },
                    LinkWireMessage::Request(req) => {
                        // Currently, not pipelining here
                        if let Some(serve) = &self.rpc_serve {
                            let resp = serve.respond_raw(req).await;
                            self_handle.send(LinkMsg::Response(resp)).await?;
                        }
                    }
                    LinkWireMessage::Response(resp) => {
                        if let Some(chan) = self.inflight_rpc.lock().remove(&resp.id) {
                            let _ = chan.send(resp);
                        }
                    }
                }
            }
        };

        let result: anyhow::Result<()> = upload_loop.race(download_loop).await;
        if let Err(err) = result {
            tracing::warn!(
                remote = debug(self.remote),
                err = debug(err),
                "link process stopped"
            );
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
enum LinkWireMessage {
    Message(Bytes),
    Request(JrpcRequest),
    Response(JrpcResponse),
}
