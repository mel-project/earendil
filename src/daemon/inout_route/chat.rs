use crate::daemon::inout_route::LinkClient;
use crate::daemon::settlement::{SettlementProof, SettlementRequest};
use crate::daemon::{context::DaemonContext, db::db_read};
use anyhow::Context;
use dashmap::DashMap;
use earendil_crypt::{ClientId, RelayFingerprint};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::SystemTime,
};

use crate::daemon::context::{
    CtxField, CLIENT_TABLE, GLOBAL_IDENTITY, NEIGH_TABLE_NEW, RELAY_GRAPH, SETTLEMENTS,
};

static CHATS: CtxField<Chats> = |ctx| {
    let max_chat_len = usize::MAX;
    let ctx = ctx.clone();

    smolscale::block_on(async move {
        match db_read(&ctx, "chats").await {
            Ok(Some(chats)) => {
                tracing::debug!("retrieving persisted chats");
                match Chats::from_bytes(chats) {
                    Ok(chats) => chats,
                    Err(e) => {
                        tracing::warn!("error retrieving persisted chats: {e}");
                        Chats::new(max_chat_len)
                    }
                }
            }
            _ => {
                tracing::debug!("no persisted chats");
                Chats::new(max_chat_len)
            }
        }
    })
};

pub fn incoming_client_chat(ctx: &DaemonContext, neighbor: ClientId, msg: String) {
    let chats = ctx.get(CHATS);
    let entry = ChatEntry::new_incoming(msg);
    chats.insert_client(neighbor, entry);
}

pub fn incoming_relay_chat(ctx: &DaemonContext, neighbor: RelayFingerprint, msg: String) {
    let chats = ctx.get(CHATS);
    let entry = ChatEntry::new_incoming(msg);
    chats.insert_relay(neighbor, entry);
}

pub fn list_clients(ctx: &DaemonContext) -> Vec<ClientId> {
    ctx.get(CLIENT_TABLE).iter().map(|neigh| *neigh.0).collect()
}

pub fn list_relays(ctx: &DaemonContext) -> Vec<RelayFingerprint> {
    ctx.get(NEIGH_TABLE_NEW)
        .iter()
        .map(|neigh| *neigh.0)
        .collect()
}

pub fn list_chats(ctx: &DaemonContext) -> String {
    let mut info = "+----------------------------------+-------------------+-----------------------------------+\n".to_owned();
    info +=    "| Neighbor                         | # of Messages     | Last chat                         |\n";
    info +=    "+----------------------------------+-------------------+-----------------------------------+\n";

    for entry in ctx.get(CHATS).client_history.iter() {
        let (neigh, chat) = entry.pair();
        let num_messages = chat.len();
        if let Some(ChatEntry {
            is_mine: _,
            text,
            time,
        }) = chat.back()
        {
            info += &format!(
                "| {:<32} | {:<17} | {} {}\n",
                neigh,
                num_messages,
                text,
                create_timestamp(*time)
            );
            info += "+----------------------------------+-------------------+-----------------------------------+\n";
        }
    }

    for entry in ctx.get(CHATS).relay_history.iter() {
        let (neigh, chat) = entry.pair();
        let num_messages = chat.len();
        if let Some(ChatEntry {
            is_mine: _,
            text,
            time,
        }) = chat.back()
        {
            info += &format!(
                "| {:<32} | {:<17} | {} {}\n",
                neigh,
                num_messages,
                text,
                create_timestamp(*time)
            );
            info += "+----------------------------------+-------------------+-----------------------------------+\n";
        }
    }

    info
}

pub fn add_client_link(ctx: &DaemonContext, neighbor: ClientId, client: Arc<LinkClient>) {
    tracing::info!("adding rpc client for neighbor: {neighbor}");
    ctx.get(CHATS).client_links.insert(neighbor, client);
}

pub fn add_relay_link(ctx: &DaemonContext, neighbor: RelayFingerprint, client: Arc<LinkClient>) {
    tracing::info!("adding rpc client for neighbor: {neighbor}");
    ctx.get(CHATS).relay_links.insert(neighbor, client);
}

pub fn remove_client_link(ctx: &DaemonContext, neighbor: &ClientId) {
    tracing::info!("removing rpc client for neighbor: {neighbor}");
    ctx.get(CHATS).client_links.remove(neighbor);
}

pub fn remove_relay_link(ctx: &DaemonContext, neighbor: &RelayFingerprint) {
    tracing::info!("removing rpc client for neighbor: {neighbor}");
    ctx.get(CHATS).relay_links.remove(neighbor);
}

pub fn get_client_chat(ctx: &DaemonContext, neigh: ClientId) -> Vec<(bool, String, SystemTime)> {
    ctx.get(CHATS)
        .get_client(neigh)
        .iter()
        .map(|entry| (entry.is_mine, entry.text.clone(), entry.time))
        .collect()
}

pub fn get_relay_chat(
    ctx: &DaemonContext,
    neigh: RelayFingerprint,
) -> Vec<(bool, String, SystemTime)> {
    ctx.get(CHATS)
        .get_relay(neigh)
        .iter()
        .map(|entry| (entry.is_mine, entry.text.clone(), entry.time))
        .collect()
}

#[tracing::instrument(skip(ctx))]
pub async fn send_client_chat_msg(
    ctx: &DaemonContext,
    dest: ClientId,
    msg: String,
) -> anyhow::Result<()> {
    todo!("pending new design for settlement authentication");
    // let chats = ctx.get(CHATS);
    // let my_sk = *ctx.get(GLOBAL_IDENTITY);
    // let settlements = ctx.get(SETTLEMENTS);

    // if msg.starts_with("!settle ") {
    //     let tokens: Vec<&str> = msg.split(' ').collect();
    //     let maybe_amount = if tokens.len() == 2 {
    //         match tokens[1].parse::<u64>() {
    //             Ok(amount) => Some(amount),
    //             Err(_) => {
    //                 log::warn!("invalid settlement syntax. !settle <amount in micromel>");
    //                 None
    //             }
    //         }
    //     } else {
    //         None
    //     };

    //     if let Some(amount) = maybe_amount {
    //         if let Some(client) = chats.client_links.get(&dest) {
    //             let proof = SettlementProof::Manual;
    //             let req_msg_str = format!("sent you a settlement request for {amount}. Accept with '!accept' or reject with '!reject'.");
    //             let req_msg = format!(
    //                 "<{}> {}",
    //                 my_sk.public().fingerprint().to_string(),
    //                 req_msg_str
    //             );

    //             match client.push_chat(req_msg.clone()).await {
    //                 Ok(_) => chats.insert_client(dest, ChatEntry::new_outgoing(msg)),
    //                 Err(e) => log::warn!("error pushing chat: {e}"),
    //             };

    //             let response = client
    //                 .start_settlement(SettlementRequest::new(my_sk, amount, proof))
    //                 .await;
    //             let res_msg = match response {
    //                 Ok(Some(res)) => {
    //                     let descriptor = ctx
    //                         .get(CLIENT_TABLE)
    //                         .get(&dest)
    //                         .context(format!("missing neighbor <{dest}> in relay graph"))?;
    //                     descriptor
    //                         .identity_pk
    //                         .verify(res.to_sign().as_bytes(), &res.signature)?;

    //                     format!("<{dest}> accepted your settlement request for {amount} micromel")
    //                 }
    //                 Ok(None) => {
    //                     format!("<{dest}> rejected your settlement request for {amount} micromel")
    //                 }
    //                 Err(e) => format!("error sending <{dest}> a settlement request: {e}"),
    //             };

    //             chats.insert_client(dest, ChatEntry::new_incoming(res_msg));
    //         }
    //     }
    // } else if msg == "!accept" {
    //     if let Some(request) = settlements.get_request(&dest) {
    //         match settlements.accept_response(&ctx, dest, request).await {
    //             Ok(_) => chats.insert_client(dest, ChatEntry::new_outgoing(msg)),
    //             Err(e) => log::warn!("error pushing chat: {e}"),
    //         }
    //     }
    // } else if msg == "!reject" {
    //     match settlements.reject_response(&dest).await {
    //         Ok(_) => chats.insert_client(dest, ChatEntry::new_outgoing(msg)),
    //         Err(e) => log::warn!("error pushing chat: {e}"),
    //     }
    // } else if let Some(client) = chats.relay_links.get(&dest) {
    //     match client.push_chat(msg.clone()).await {
    //         Ok(_) => chats.insert_client(dest, ChatEntry::new_outgoing(msg)),
    //         Err(e) => tracing::warn!("error pushing chat: {e}"),
    //     }
    // }

    // Ok(())
}

#[tracing::instrument(skip(ctx))]
pub async fn send_relay_chat_msg(
    ctx: &DaemonContext,
    dest: RelayFingerprint,
    msg: String,
) -> anyhow::Result<()> {
    let chats = ctx.get(CHATS);
    let my_sk = ctx
        .get(GLOBAL_IDENTITY)
        .expect("only relays have global identities");
    let settlements = ctx.get(SETTLEMENTS);

    if msg.starts_with("!settle ") {
        let tokens: Vec<&str> = msg.split(' ').collect();
        let maybe_amount = if tokens.len() == 2 {
            match tokens[1].parse::<u64>() {
                Ok(amount) => Some(amount),
                Err(_) => {
                    log::warn!("invalid settlement syntax. !settle <amount in micromel>");
                    None
                }
            }
        } else {
            None
        };

        if let Some(amount) = maybe_amount {
            if let Some(relay_link) = chats.relay_links.get(&dest) {
                let proof = SettlementProof::Manual;
                let req_msg_str = format!("sent you a settlement request for {amount}. Accept with '!accept' or reject with '!reject'.");
                let req_msg = format!(
                    "<{}> {}",
                    my_sk.public().fingerprint().to_string(),
                    req_msg_str
                );

                match relay_link.push_chat_relay(req_msg.clone()).await {
                    Ok(_) => chats.insert_relay(dest, ChatEntry::new_outgoing(msg)),
                    Err(e) => log::warn!("error pushing chat: {e}"),
                };

                let response = relay_link
                    .start_settlement(SettlementRequest::new(my_sk, amount, proof))
                    .await;
                let res_msg = match response {
                    Ok(Some(res)) => {
                        let descriptor = ctx
                            .get(RELAY_GRAPH)
                            .read()
                            .identity(&dest)
                            .context(format!("missing neighbor <{dest}> in relay graph"))?;
                        descriptor
                            .identity_pk
                            .verify(res.to_sign().as_bytes(), &res.signature)?;

                        format!("<{dest}> accepted your settlement request for {amount} micromel")
                    }
                    Ok(None) => {
                        format!("<{dest}> rejected your settlement request for {amount} micromel")
                    }
                    Err(e) => format!("error sending <{dest}> a settlement request: {e}"),
                };

                chats.insert_relay(dest, ChatEntry::new_incoming(res_msg));
            }
        }
    } else if msg == "!accept" {
        if let Some(request) = settlements.get_request(&dest) {
            match settlements.accept_response(&ctx, dest, request).await {
                Ok(_) => chats.insert_relay(dest, ChatEntry::new_outgoing(msg)),
                Err(e) => log::warn!("error pushing chat: {e}"),
            }
        }
    } else if msg == "!reject" {
        match settlements.reject_response(&dest).await {
            Ok(_) => chats.insert_relay(dest, ChatEntry::new_outgoing(msg)),
            Err(e) => log::warn!("error pushing chat: {e}"),
        }
    } else if let Some(client) = chats.relay_links.get(&dest) {
        match client.push_chat_relay(msg.clone()).await {
            Ok(_) => chats.insert_relay(dest, ChatEntry::new_outgoing(msg)),
            Err(e) => tracing::warn!("error pushing chat: {e}"),
        }
    }

    Ok(())
}

pub fn serialize_chats(ctx: &DaemonContext) -> anyhow::Result<Vec<u8>> {
    ctx.get(CHATS).clone().into_bytes()
}

pub fn create_timestamp(now: SystemTime) -> String {
    let datetime: chrono::DateTime<chrono::Local> = now.into();

    format!("[{}]", datetime.format("%Y-%m-%d %H:%M:%S"))
}

#[derive(Clone)]
struct Chats {
    client_history: DashMap<ClientId, VecDeque<ChatEntry>>,
    relay_history: DashMap<RelayFingerprint, VecDeque<ChatEntry>>,
    client_links: DashMap<ClientId, Arc<LinkClient>>,
    relay_links: DashMap<RelayFingerprint, Arc<LinkClient>>,
    max_chat_len: usize,
}

#[derive(Clone, Serialize, Deserialize)]
struct ChatEntry {
    is_mine: bool,
    text: String,
    time: SystemTime,
}

impl Chats {
    fn new(max_chat_len: usize) -> Self {
        let client_history: DashMap<ClientId, VecDeque<ChatEntry>> = DashMap::new();
        let relay_history: DashMap<RelayFingerprint, VecDeque<ChatEntry>> = DashMap::new();
        let client_links: DashMap<ClientId, Arc<LinkClient>> = DashMap::new();
        let relay_links: DashMap<RelayFingerprint, Arc<LinkClient>> = DashMap::new();
        Self {
            client_history,
            relay_history,
            client_links,
            relay_links,
            max_chat_len,
        }
    }

    fn insert_client(&self, neighbor: ClientId, entry: ChatEntry) {
        let mut chat = self.client_history.entry(neighbor).or_default();
        if chat.len() >= self.max_chat_len {
            chat.pop_front();
        }

        chat.push_back(entry);
    }

    fn insert_relay(&self, neighbor: RelayFingerprint, entry: ChatEntry) {
        let mut chat = self.relay_history.entry(neighbor).or_default();
        if chat.len() >= self.max_chat_len {
            chat.pop_front();
        }

        chat.push_back(entry);
    }

    fn get_client(&self, neighbor: ClientId) -> Vec<ChatEntry> {
        self.client_history
            .get(&neighbor)
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    fn get_relay(&self, neighbor: RelayFingerprint) -> Vec<ChatEntry> {
        self.relay_history
            .get(&neighbor)
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    fn into_bytes(self) -> anyhow::Result<Vec<u8>> {
        let client_history: HashMap<ClientId, VecDeque<ChatEntry>> =
            self.client_history.into_iter().collect();
        let relay_history: HashMap<RelayFingerprint, VecDeque<ChatEntry>> =
            self.relay_history.into_iter().collect();
        Ok(stdcode::serialize(&(
            client_history,
            relay_history,
            self.max_chat_len,
        ))?)
    }

    fn from_bytes(bytes: Vec<u8>) -> anyhow::Result<Self> {
        let (client_history, relay_history, max_chat_len): (
            HashMap<ClientId, VecDeque<ChatEntry>>,
            HashMap<RelayFingerprint, VecDeque<ChatEntry>>,
            usize,
        ) = stdcode::deserialize(&bytes)?;
        Ok(Self {
            client_history: client_history.into_iter().collect(),
            relay_history: relay_history.into_iter().collect(),
            client_links: DashMap::new(),
            relay_links: DashMap::new(),
            max_chat_len,
        })
    }
}

impl ChatEntry {
    fn new_outgoing(text: String) -> Self {
        Self {
            is_mine: true,
            text,
            time: SystemTime::now(),
        }
    }

    fn new_incoming(text: String) -> Self {
        Self {
            is_mine: false,
            text,
            time: SystemTime::now(),
        }
    }
}
