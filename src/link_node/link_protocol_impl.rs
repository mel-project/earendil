use async_trait::async_trait;

use earendil_crypt::RelayFingerprint;

use earendil_topology::{AdjacencyDescriptor, IdentityDescriptor};

use itertools::Itertools;

use crate::ChatEntry;

use super::{
    link_protocol::{InfoResponse, LinkProtocol, LinkRpcErr},
    types::NodeId,
    LinkNodeCtx,
};

pub struct LinkProtocolImpl {
    pub ctx: LinkNodeCtx,
    pub remote_id: NodeId,
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
            .relay_config
            .as_ref()
            .expect("only relays have global identities")
            .0;
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
        let chat_entry = ChatEntry {
            timestamp: chrono::offset::Utc::now().timestamp(),
            text: msg,
            is_outgoing: false,
        };
        self.ctx
            .store
            .insert_chat_entry(self.remote_id, chat_entry)
            .await
            .map_err(|_| LinkRpcErr::PushChatFailed)
    }

    #[tracing::instrument(skip(self))]
    async fn get_ott(&self) -> Result<String, LinkRpcErr> {
        self.ctx
            .store
            .get_ott()
            .await
            .map_err(|e| LinkRpcErr::InternalServerError(e.to_string()))
    }

    #[tracing::instrument(skip(self))]
    async fn send_payment_proof(
        &self,
        amount: u64,
        paysystem_name: String,
        proof: String,
    ) -> Result<(), LinkRpcErr> {
        let neigh = self.remote_id;
        if let Some(paysystem) = self.ctx.payment_systems.get(&paysystem_name) {
            if paysystem
                .verify_payment(neigh, amount, &proof)
                .await
                .map_err(|e| {
                    tracing::warn!("payment verification failed: {:?}", e);
                    LinkRpcErr::PaymentVerificationFailed(e.to_string())
                })?
            {
                self.ctx
                    .store
                    .insert_debt_entry(
                        neigh,
                        crate::DebtEntry {
                            delta: amount as _,
                            timestamp: chrono::offset::Utc::now().timestamp(),
                            proof: Some(proof),
                        },
                    )
                    .await
                    .map_err(|e| {
                        tracing::warn!("could not insert debt entry: {:?}", e);
                        LinkRpcErr::InternalServerError(e.to_string())
                    })?;
                tracing::debug!(
                    "successly received payment proof from {:?} for {amount}",
                    neigh
                );
                return Ok(());
            } else {
                tracing::debug!("invalid payment proof");
                return Err(LinkRpcErr::InvalidPaymentProof);
            }
        } else {
            return Err(LinkRpcErr::UnacceptedPaysystem);
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
