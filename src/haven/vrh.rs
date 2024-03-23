use bytes::Bytes;
use earendil_crypt::{AnonEndpoint, HavenIdentityPublic};
use earendil_packet::crypt::DhPublic;
use serde::{Deserialize, Serialize};

use super::HavenEndpoint;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct V2rMessage {
    pub dest_haven: HavenEndpoint,
    pub payload: HavenMsg,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct H2rMessage {
    pub dest_visitor: AnonEndpoint,
    pub payload: HavenMsg,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct R2hMessage {
    pub src_visitor: AnonEndpoint,
    pub payload: HavenMsg,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum HavenMsg {
    VisitorHs(VisitorHandshake),
    HavenHs(HavenHandshake),
    Regular(Bytes),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HavenHandshake {
    pub id_pk: HavenIdentityPublic,
    pub eph_pk: DhPublic,
    pub sig: Bytes,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VisitorHandshake(pub DhPublic);
