mod dht;
mod global_rpc;
mod packet_conn;
mod vrh;

use std::sync::Arc;

use earendil_crypt::{HavenEndpoint, HavenFingerprint};
use moka::future::Cache;

use crate::n2r_node::N2rNode;

pub use self::packet_conn::HavenPacketConn;

const HAVEN_FORWARD_DOCK: u32 = 100002;

pub struct V2hNode {
    ctx: V2hNodeCtx,
}

impl V2hNode {
    pub fn new(_n2r: N2rNode, _cfg: V2hConfig) -> Self {
        todo!()
    }

    pub async fn connect_packet(&self, dest: HavenEndpoint) -> anyhow::Result<HavenPacketConn> {
        let conn = HavenPacketConn::connect(&self.ctx, dest).await?;
        Ok(conn)
    }
}

#[derive(Clone)]
struct V2hNodeCtx {
    n2r: Arc<N2rNode>,
}

pub struct V2hConfig {}
