use std::hash::Hash;

use arrayref::array_ref;
use bytemuck::{Pod, Zeroable};
use earendil_crypt::{AnonEndpoint, ClientId, RelayFingerprint, RemoteId};
use rand::{Rng, RngCore};
use rand_distr::Exp;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;

use crate::{
    crypt::{box_decrypt, box_encrypt, stream_dencrypt, DhPublic, DhSecret, BOX_OVERHEAD},
    InnerPacket, ReplyBlock,
};

const RAW_BODY_SIZE: usize = 8192;
const MAX_HOPS: usize = 10;
const LOW_LATENCY_MS: u16 = 15;
const METADATA_BUFFER_SIZE: usize = 35;
const FORWARD_TO_CLIENT_FLAG: u8 = 2;
const FORWARD_TO_RELAY_FLAG: u8 = 1;
const PACKET_IS_OURS_FLAG: u8 = 0;
const RAW_HEADER_SIZE: usize = std::mem::size_of::<RawHeader>();
const INNER_HEADER_SIZE: usize = HEADER_LAYER_SIZE * (MAX_HOPS - 1);
const HEADER_LAYER_SIZE: usize = METADATA_BUFFER_SIZE + BOX_OVERHEAD;
pub const RAW_PACKET_SIZE: usize = std::mem::size_of::<RawPacket>();

pub type RawBody = [u8; 8192];

/// A raw, on-the-wire Earendil packet.
#[repr(C)]
#[derive(Pod, Clone, Copy, Zeroable, Debug, PartialEq, Eq, Hash)]
pub struct RawPacket {
    pub header: RawHeader,
    pub onion_body: RawBody,
}

/// An instruction for forwarding one layer of the onion.
#[derive(Clone, Copy, Debug)]
pub struct ForwardInstruction {
    /// The DH public key of this hop
    pub this_pubkey: DhPublic,
    /// The unique id of the next hop
    pub next_hop: RelayFingerprint,
}

#[derive(Error, Serialize, Deserialize, Debug)]
pub enum PacketConstructError {
    #[error("route contains too many hops")]
    TooManyHops,
    #[error("message too big")]
    MessageTooBig,
    #[error("mismatched nodes")]
    MismatchedNodes,
}

#[derive(thiserror::Error, Debug)]
pub enum PacketPeelError {
    #[error("decrypting header failed")]
    DecryptionError,
    #[error("opening inner packet failed")]
    InnerPacketOpenError,
}

fn sample_delay(avg: u16) -> u16 {
    let exp = Exp::new(1.0 / avg as f64).expect("avg must be greater than zero");
    let mut rng = rand::thread_rng();
    rng.sample(exp) as u16
}

impl RawPacket {
    pub fn new_normal(
        route: &[ForwardInstruction],
        dest_opk: &DhPublic,
        payload: InnerPacket,
        my_id: RemoteId,
    ) -> Result<Self, PacketConstructError> {
        let (raw, _) = Self::new(route, dest_opk, false, payload, &[0; 32], my_id)?;
        Ok(raw)
    }

    /// Creates a RawPacket for a message to an anonymous identity, using a ReplyBlock
    pub fn new_reply(
        reply_block: &ReplyBlock,
        payload: InnerPacket,
        my_id: &RemoteId,
    ) -> Result<Self, PacketConstructError> {
        let mut raw = payload
            .encode(my_id)
            .map_err(|_| PacketConstructError::MessageTooBig)?;

        stream_dencrypt(&reply_block.stream_key, &[0; 12], &mut raw);

        Ok(Self {
            header: reply_block.header,
            onion_body: raw,
        })
    }

    /// Creates a new RawPacket along with a vector of the shared secrets used to encrypt each layer of the onion body, given a payload and the series of relays that the packet is supposed to be peeled by.
    pub(crate) fn new(
        route: &[ForwardInstruction],
        dest_opk: &DhPublic,
        dest_is_client: bool,
        payload: InnerPacket,
        metadata: &[u8; 32],
        my_id: RemoteId,
    ) -> Result<(Self, Vec<[u8; 32]>), PacketConstructError> {
        if route.len() >= MAX_HOPS {
            return Err(PacketConstructError::TooManyHops);
        }

        let delay = sample_delay(LOW_LATENCY_MS);

        // Use a recursive algorithm. Base case: the route is empty
        if route.is_empty() {
            let sealed_payload = payload
                .encode(&my_id)
                .map_err(|_| PacketConstructError::MessageTooBig)?;

            let buffer = if dest_is_client {
                // we need to forward to a client so metadata starts with 2
                let mut buffer = [2; METADATA_BUFFER_SIZE];

                // encode client id and rb id
                buffer[1..17].copy_from_slice(&metadata[..16]);

                buffer
            } else {
                // this packet's dest is a relay, so metadata starts with 0
                let mut buffer = [0; METADATA_BUFFER_SIZE];

                // encode relay fingerprint
                buffer[1..33].copy_from_slice(metadata);
                // encode packet latency
                buffer[33..].copy_from_slice(&delay.to_be_bytes());

                buffer
            };

            let (header_outer, our_sk) = box_encrypt(&buffer, dest_opk);
            let shared_sec = our_sk.shared_secret(dest_opk);
            let onion_body = {
                let body_key = blake3::keyed_hash(b"body____________________________", &shared_sec);
                let mut new = sealed_payload;
                stream_dencrypt(body_key.as_bytes(), &[0; 12], &mut new);
                new
            };

            Ok((
                Self {
                    header: RawHeader {
                        outer: header_outer.try_into().unwrap(),
                        inner: {
                            // We fill with garbage, since none of this will get read
                            let mut bts = [0; INNER_HEADER_SIZE];
                            rand::thread_rng().fill_bytes(&mut bts);
                            bts
                        },
                    },
                    onion_body,
                },
                vec![shared_sec],
            ))
        } else {
            // we need to forward to a relay so metadata starts with 1
            let mut buffer = [1; 35];
            // encode relay fingerprint
            buffer[1..33].copy_from_slice(route[0].next_hop.as_bytes());

            let (next_hop, mut shared_secs) = RawPacket::new(
                &route[1..],
                dest_opk,
                dest_is_client,
                payload,
                metadata,
                my_id,
            )?;

            buffer[33..].copy_from_slice(&delay.to_be_bytes());
            let (header_outer, our_sk) = box_encrypt(&buffer, &route[0].this_pubkey);
            let shared_sec = our_sk.shared_secret(&route[0].this_pubkey);
            let onion_body = {
                let body_key = blake3::keyed_hash(b"body____________________________", &shared_sec);
                let mut new = next_hop.onion_body;
                stream_dencrypt(body_key.as_bytes(), &[0; 12], &mut new);
                new
            };
            let header_inner = {
                let header_key =
                    blake3::keyed_hash(b"header__________________________", &shared_sec);
                // Shift the first 690-69 bytes of the next-hop header backwards by 69 bytes and encrypt.
                // This drops the last 69 bytes, but we know that that cannot possibly include any useful info because of the 10-hop limit.
                let mut new_header_inner = *array_ref![
                    bytemuck::cast_ref::<_, [u8; RAW_HEADER_SIZE]>(&next_hop.header),
                    0,
                    INNER_HEADER_SIZE
                ];
                stream_dencrypt(header_key.as_bytes(), &[0; 12], &mut new_header_inner);
                new_header_inner
            };
            shared_secs.push(shared_sec);
            Ok((
                Self {
                    header: RawHeader {
                        outer: header_outer.try_into().unwrap(),
                        inner: header_inner,
                    },
                    onion_body,
                },
                shared_secs,
            ))
        }
    }

    /// "Peels off" one layer of the onion, by decryption using the specified secret key.
    pub fn peel(&self, our_sk: &DhSecret) -> Result<PeeledPacket, PacketPeelError> {
        // First, decode the header
        let (metadata, their_pk) = box_decrypt(&self.header.outer, our_sk)
            .map_err(|_| PacketPeelError::DecryptionError)?;
        assert_eq!(metadata.len(), METADATA_BUFFER_SIZE);
        let shared_sec = our_sk.shared_secret(&their_pk);

        // Then, peel the header
        let peeled_header = {
            let header_key = blake3::keyed_hash(b"header__________________________", &shared_sec);
            let mut buffer = [0u8; RAW_HEADER_SIZE];
            buffer[..INNER_HEADER_SIZE].copy_from_slice(&self.header.inner);
            stream_dencrypt(header_key.as_bytes(), &[0; 12], &mut buffer);
            buffer
        };
        // Then, peel the body
        let peeled_body = {
            let body_key = blake3::keyed_hash(b"body____________________________", &shared_sec);
            let mut new = self.onion_body;
            stream_dencrypt(body_key.as_bytes(), &[0; 12], &mut new);
            new
        };

        Ok(if metadata[0] == FORWARD_TO_CLIENT_FLAG {
            // if the metadata starts with 2, then we need to forward to a client
            // the subsequent 8 bytes in the metadata indicate the client ID of the next guy.
            // bytes 9..17 (inclusive!) is a 64-bit reply block identifier that we will use to pair this packet with the reply block we generated, with which the other side garbled this message.
            let client_id: u64 = u64::from_be_bytes(*array_ref![metadata, 1, 8]);
            let id_bts = array_ref![metadata, 9, 8];
            let rb_id = u64::from_be_bytes(*id_bts);
            PeeledPacket::GarbledReply {
                client_id,
                rb_id,
                pkt: peeled_body,
            }
        } else if metadata[0] == FORWARD_TO_RELAY_FLAG {
            // if the metadata starts with 1, then we need to forward to a relay.
            // the 20 remaining bytes in the metadata indicate the fingerprint of the next guy.
            let fingerprint = RelayFingerprint::from_bytes(array_ref![metadata, 1, 32]);
            let delay_bytes: [u8; 2] = match metadata[33..] {
                [a, b] => [a, b],
                _ => return Err(PacketPeelError::InnerPacketOpenError),
            };
            PeeledPacket::Relay {
                next_peeler: fingerprint,
                pkt: RawPacket {
                    header: bytemuck::cast(peeled_header),
                    onion_body: peeled_body,
                },
                delay_ms: u16::from_be_bytes(delay_bytes),
            }
        } else if metadata[0] == PACKET_IS_OURS_FLAG {
            // otherwise, the packet is ours
            let (inner_pkt, anon_remote) = InnerPacket::decode(&peeled_body)
                .map_err(|_| PacketPeelError::InnerPacketOpenError)?;
            let anon_remote = match anon_remote {
                RemoteId::Relay(_) => return Err(PacketPeelError::InnerPacketOpenError),
                RemoteId::Anon(anon) => anon,
            };
            PeeledPacket::Received {
                from: anon_remote,
                pkt: inner_pkt,
            }
        } else {
            return Err(PacketPeelError::InnerPacketOpenError);
        })
    }
}

/// The raw, encrypted header of an Earendil packet.
#[derive(Pod, Clone, Copy, Zeroable, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct RawHeader {
    /// Box-encrypted, 21-byte flag (1 byte) + fingerprint OR metadata (20 bytes)
    #[serde(with = "BigArray")]
    pub outer: [u8; HEADER_LAYER_SIZE],
    /// Padding so that header is fixed-size
    #[serde(with = "BigArray")]
    pub inner: [u8; INNER_HEADER_SIZE],
}

/// A "peeled" Earendil packet.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Eq)]
pub enum PeeledPacket {
    Relay {
        next_peeler: RelayFingerprint,
        pkt: RawPacket,
        delay_ms: u16,
    },
    Received {
        from: AnonEndpoint,
        pkt: InnerPacket,
    },
    GarbledReply {
        client_id: ClientId,
        rb_id: u64,
        pkt: [u8; RAW_BODY_SIZE],
    },
}
