use async_trait::async_trait;

use earendil_crypt::{ClientId, RelayFingerprint};

use earendil_topology::{AdjacencyDescriptor, IdentityDescriptor};

use itertools::Itertools;

use super::{
    link_protocol::{InfoResponse, LinkProtocol},
    settlement::{Seed, SettlementRequest, SettlementResponse},
    LinkNodeCtx,
};

pub struct LinkProtocolImpl {
    pub ctx: LinkNodeCtx,

    pub remote_client_id: ClientId,
    pub remote_relay_fp: Option<RelayFingerprint>,
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
        // let all_nodes: Vec<_> = self.ctx.relay_graph.read().all_nodes().collect();
        // println!("{:?}", all_nodes);
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
    async fn start_settlement(&self, _req: SettlementRequest) -> Option<SettlementResponse> {
        todo!()
    }

    #[tracing::instrument(skip(self))]
    async fn push_chat(&self, _msg: String) {
        todo!()
    }

    #[tracing::instrument(skip(self))]
    async fn request_seed(&self) -> Option<Seed> {
        todo!()
    }
}
