mod inout_route;
mod link_proc;

use ahash::AHashMap;
use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use clone_macro::clone;
use derivative::Derivative;
use earendil_crypt::{ClientId, RelayFingerprint, RelayIdentitySecret};
use futures_util::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use inout_route::{process_in_route, process_out_route};
use itertools::Itertools;
use nanorpc::{JrpcRequest, JrpcResponse, RpcService, ServerError};
use rand::Rng;
use smolscale::immortal::{Immortal, RespawnStrategy};

use std::{collections::BTreeMap, convert::Infallible};

use earendil_packet::RawPacketWithNext;

use haiyuu::{Handle, WeakHandle};
use link_proc::{LinkMsg, LinkProcess};

use crate::{
    config::{InRouteConfig, OutRouteConfig},
    link_node::client_proc::ClientMsg,
};

use super::{
    client_proc::ClientProcess,
    netgraph::{NeighborGuard, NetGraph},
    relay_proc::{RelayMsg, RelayProcess},
    NeighborId,
};

pub struct SwitchProcess {
    role: either::Either<
        (RelayIdentitySecret, WeakHandle<RelayProcess>),
        (ClientId, WeakHandle<ClientProcess>),
    >,
    graph: NetGraph,

    relays: AHashMap<RelayFingerprint, (Handle<LinkProcess>, NeighborGuard)>,
    clients: AHashMap<ClientId, (Handle<LinkProcess>, NeighborGuard)>,

    in_routes: BTreeMap<String, InRouteConfig>,
    out_routes: BTreeMap<String, OutRouteConfig>,
}

#[derive(Clone)]
struct RpcImpl(WeakHandle<RelayProcess>);

#[async_trait]
impl RpcService for RpcImpl {
    async fn respond(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> Option<Result<serde_json::Value, ServerError>> {
        let id = rand::thread_rng().gen();
        let req = JrpcRequest {
            jsonrpc: "2.0".into(),
            method: method.to_string(),
            params,
            id: nanorpc::JrpcId::Number(id),
        };
        let (send, recv) = oneshot::channel();
        let _ = self.0.send(RelayMsg::LinkRpc(req, send)).await;
        let resp = if let Ok(resp) = recv.await {
            resp
        } else {
            return None;
        };
        if let Some(err) = resp.error {
            Some(Err(ServerError {
                code: err.code as _,
                message: err.message,
                details: err.data,
            }))
        } else {
            Some(Ok(resp.result.unwrap()))
        }
    }
}

impl SwitchProcess {
    pub fn new_client(
        identity: ClientId,
        process: WeakHandle<ClientProcess>,
        graph: NetGraph,
        out_routes: BTreeMap<String, OutRouteConfig>,
    ) -> Self {
        Self {
            role: either::Either::Right((identity, process)),

            relays: AHashMap::new(),
            clients: AHashMap::new(),
            in_routes: Default::default(),
            out_routes,
            graph,
        }
    }

    pub fn new_relay(
        identity: RelayIdentitySecret,
        process: WeakHandle<RelayProcess>,
        graph: NetGraph,
        in_routes: BTreeMap<String, InRouteConfig>,
        out_routes: BTreeMap<String, OutRouteConfig>,
    ) -> Self {
        Self {
            role: either::Either::Left((identity, process)),
            relays: AHashMap::new(),
            clients: AHashMap::new(),
            graph,
            in_routes,
            out_routes,
        }
    }

    fn identity(&self) -> either::Either<RelayIdentitySecret, ClientId> {
        self.role.as_ref().map_either(|l| l.0, |r| r.0)
    }

    fn role_proc(&self) -> either::Either<&WeakHandle<RelayProcess>, &WeakHandle<ClientProcess>> {
        self.role.as_ref().map_either(|l| &l.1, |r| &r.1)
    }

    fn rpc(&self) -> Option<RpcImpl> {
        if let either::Either::Left(proc) = self.role_proc() {
            Some(RpcImpl(proc.clone()))
        } else {
            None
        }
    }
}

impl haiyuu::Process for SwitchProcess {
    type Message = SwitchMessage;

    type Output = Infallible;

    async fn run(&mut self, mailbox: &mut haiyuu::Mailbox<Self>) -> Infallible {
        // set up link tasks
        let handle = mailbox.handle();
        let rpc = self.rpc();
        let _in_routes = self
            .in_routes
            .values()
            .cloned()
            .map(|route| {
                Immortal::respawn(
                    RespawnStrategy::Immediate,
                    clone!([handle, rpc], move || {
                        process_in_route(route.clone(), handle.clone(), rpc.clone())
                    }),
                )
            })
            .collect_vec();
        let _out_routes = self
            .out_routes
            .values()
            .cloned()
            .map(|route| {
                let identity = self.identity();
                Immortal::respawn(
                    RespawnStrategy::Immediate,
                    clone!([handle, route, rpc], move || process_out_route(
                        route.clone(),
                        handle.clone(),
                        identity,
                        rpc.clone()
                    )),
                )
            })
            .collect_vec();

        loop {
            let message = mailbox.recv().await;
            let msg_debug = format!("{:?}", message);
            let fallible = async {
                match message {
                    SwitchMessage::ToRelay(bts, relay) => {
                        self.relays
                            .get(&relay)
                            .context("could not find link to relay")?
                            .0
                            .send(LinkMsg::Message(bts.clone()))
                            .await?;
                    }

                    SwitchMessage::ToClient(bts, client) => {
                        self.clients
                            .get(&client)
                            .context("could not find link to client")?
                            .0
                            .send(LinkMsg::Message(bts.clone()))
                            .await?;
                    }

                    SwitchMessage::FromClient(bts, _) | SwitchMessage::FromRelay(bts, _) => {
                        match self.role_proc() {
                            either::Either::Left(relay) => {
                                let rpnx: &RawPacketWithNext = bytemuck::try_from_bytes(&bts)
                                    .ok()
                                    .context("cannot cast as RawPacketWithNext")?;
                                relay.send(RelayMsg::PeelForward(Box::new(*rpnx))).await?;
                            }
                            either::Either::Right(client) => {
                                let (rb_id, bts): (u64, Bytes) = stdcode::deserialize(&bts)?;
                                client.send(ClientMsg::Backward(rb_id, bts)).await?;
                            }
                        }
                    }
                    SwitchMessage::NewClientLink(link, client) => {
                        self.clients.insert(
                            client,
                            (link, self.graph.neighbor_guard(NeighborId::Client(client))),
                        );
                    }
                    SwitchMessage::NewRelayLink(link, relay) => {
                        self.relays.insert(
                            relay,
                            (link, self.graph.neighbor_guard(NeighborId::Relay(relay))),
                        );
                    }

                    SwitchMessage::CallLinkRpc(relay_fingerprint, jrpc_request, sender) => {
                        self.relays
                            .get(&relay_fingerprint)
                            .context("could not find link to relay")?
                            .0
                            .send(LinkMsg::Request(jrpc_request, sender))
                            .await?;
                    }
                }
                anyhow::Ok(())
            };
            if let Err(err) = fallible.await {
                tracing::warn!(err = debug(err), msg_debug, "failed to handle")
            }
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
pub enum SwitchMessage {
    ToRelay(#[derivative(Debug = "ignore")] Bytes, RelayFingerprint),
    ToClient(#[derivative(Debug = "ignore")] Bytes, ClientId),

    CallLinkRpc(RelayFingerprint, JrpcRequest, oneshot::Sender<JrpcResponse>),

    FromClient(#[derivative(Debug = "ignore")] Bytes, ClientId),
    FromRelay(#[derivative(Debug = "ignore")] Bytes, RelayFingerprint),

    NewClientLink(
        #[derivative(Debug = "ignore")] Handle<LinkProcess>,
        ClientId,
    ),

    NewRelayLink(
        #[derivative(Debug = "ignore")] Handle<LinkProcess>,
        RelayFingerprint,
    ),
}

async fn write_pascal<W: AsyncWrite + Unpin>(message: &[u8], mut out: W) -> anyhow::Result<()> {
    let len = (message.len() as u32).to_be_bytes();

    out.write_all(&len).await?;
    out.write_all(message).await?;
    out.flush().await?;

    Ok(())
}

async fn read_pascal<R: AsyncRead + Unpin>(mut input: R) -> anyhow::Result<Vec<u8>> {
    let mut len = [0; 4];
    input.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len);
    if len > 500_000 {
        anyhow::bail!("pascal message that is too big")
    }
    let mut buffer = vec![0; len as usize];
    input.read_exact(&mut buffer).await?;

    Ok(buffer)
}