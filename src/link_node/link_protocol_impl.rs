use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use earendil_crypt::{ClientId, RelayFingerprint};

use earendil_topology::{AdjacencyDescriptor, IdentityDescriptor};

use itertools::Itertools;

use crate::ChatEntry;

use super::{
    link_protocol::{InfoResponse, LinkProtocol, LinkRpcErr},
    payment_dest::{DummyPayDest, PaymentMethod},
    types::NeighborId,
    LinkNodeCtx, RouteConfig,
};

pub struct LinkProtocolImpl {
    pub ctx: LinkNodeCtx,
    pub remote_client_id: ClientId,
    pub remote_relay_fp: Option<RelayFingerprint>,
    pub route_config: RouteConfig,
}

#[async_trait]
impl LinkProtocol for LinkProtocolImpl {
    async fn info(&self) -> InfoResponse {
        InfoResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    #[tracing::instrument(skip(self))]
    async fn sign_adjacency(
        &self,
        mut left_incomplete: AdjacencyDescriptor,
    ) -> Option<AdjacencyDescriptor> {
        let my_sk = self
            .ctx
            .cfg
            .my_idsk
            .expect("only relays have global identities");
        let my_fp = my_sk.public().fingerprint();
        // This must be a neighbor that is "left" of us
        let valid = left_incomplete.left < left_incomplete.right && left_incomplete.right == my_fp;
        if !valid {
            tracing::debug!("neighbor not right of us! Refusing to sign adjacency x_x");
            return None;
        }
        // Fill in the right-hand-side
        let signature = my_sk.sign(left_incomplete.to_sign().as_bytes());
        left_incomplete.right_sig = signature;

        self.ctx
            .relay_graph
            .write()
            .insert_adjacency(left_incomplete.clone())
            .map_err(|e| {
                tracing::warn!("could not insert here: {:?}", e);
                e
            })
            .ok()?;
        Some(left_incomplete)
    }

    async fn identity(&self, fp: RelayFingerprint) -> Option<IdentityDescriptor> {
        self.ctx.relay_graph.read().identity(&fp)
    }

    #[tracing::instrument(skip(self))]
    async fn adjacencies(&self, fps: Vec<RelayFingerprint>) -> Vec<AdjacencyDescriptor> {
        let rg = self.ctx.relay_graph.read();
        fps.into_iter()
            .flat_map(|fp| rg.adjacencies(&fp).into_iter().flatten())
            .dedup()
            .collect()
    }

    #[tracing::instrument(skip(self))]
    async fn push_chat(&self, msg: String) -> Result<(), LinkRpcErr> {
        let neigh = match self.remote_relay_fp {
            Some(remote_relay_fp) => NeighborId::Relay(remote_relay_fp),
            None => NeighborId::Client(self.remote_client_id),
        };
        let chat_entry = ChatEntry {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| LinkRpcErr::PushChatFailed)?
                .as_secs(),
            text: msg,
            is_outgoing: false,
        };
        self.ctx
            .store
            .insert_chat_entry(neigh, chat_entry)
            .await
            .map_err(|_| LinkRpcErr::PushChatFailed)
    }

    async fn push_price(
        &self,
        price: u64,
        debt_limit: u64,
        methods: Vec<PaymentMethod>,
    ) -> Result<(), LinkRpcErr> {
        match self.route_config.clone() {
            RouteConfig::Out(config) => {
                // check if price < our max_price
                if price < config.max_price {
                    // check if any of our pay_methods ∈ their supported methods
                    let my_pay_methods = self.ctx.cfg.payment_methods.clone();
                    for my_pay_method in my_pay_methods.get_available() {
                        if methods.contains(&my_pay_method) {
                            // construct impl PaymentDestination & save to link
                            match my_pay_method {
                                PaymentMethod::Dummy => {
                                    let secret = my_pay_methods.dummy.unwrap(); // we're sure it's available
                                    let pay_dest = Box::new(DummyPayDest { secret });
                                    self.ctx.pay_dest_table.insert(
                                        self.remote_relay_fp.unwrap(), // remote of outgoing link is always a relay
                                        (debt_limit, pay_dest),
                                    );
                                }
                            }
                            return Ok(());
                        }
                    }
                    return Err(LinkRpcErr::NoSupportedPaymentMethod);
                } else {
                    return Err(LinkRpcErr::PriceTooHigh);
                }
            }
            RouteConfig::In(_) => return Err(LinkRpcErr::PushPriceInvalidDirection),
        }
    }

    // #[tracing::instrument(skip(self))]
    // async fn request_seed(&self) -> Option<Seed> {
    //     todo!()
    // }

    // #[tracing::instrument(skip(self))]
    // async fn start_settlement(&self, _req: SettlementRequest) -> Option<SettlementResponse> {
    //     todo!()
    // }
}
