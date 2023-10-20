use arrayref::array_ref;
use bytemuck::{Pod, Zeroable};
use earendil_crypt::{Fingerprint, IdentitySecret};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;

use crate::{
    crypt::{box_decrypt, box_encrypt, stream_dencrypt, OnionPublic, OnionSecret},
    InnerPacket, ReplyBlock,
};

/// A raw, on-the-wire Earendil packet.
#[repr(C)]
#[derive(Pod, Clone, Copy, Zeroable, Debug)]
pub struct RawPacket {
    pub header: RawHeader,
    pub onion_body: [u8; 8192],
}

/// An instruction for forwarding one layer of the onion.
#[derive(Clone, Copy, Debug)]
pub struct ForwardInstruction {
    /// The DH public key of this hop
    pub this_pubkey: OnionPublic,
    /// The unique fingerprint of the next hop
    pub next_fingerprint: Fingerprint,
}

#[derive(Error, Serialize, Deserialize, Debug)]
pub enum PacketConstructError {
    #[error("route contains too many hops")]
    TooManyHops,
    #[error("message too big")]
    MessageTooBig,
}

#[derive(thiserror::Error, Debug)]
pub enum PacketPeelError {
    #[error("decrypting header failed")]
    DecryptionError,
    #[error("opening inner packet failed")]
    InnerPacketOpenError,
}

impl RawPacket {
    /// Creates a new RawPacket along with a vector of the shared secrets used to encrypt each layer of the onion body, given a payload and the series of relays that the packet is supposed to pass through.
    pub fn new(
        route: &[ForwardInstruction],
        destination: &OnionPublic,
        payload: InnerPacket,
        metadata: &[u8; 20],
        my_isk: &IdentitySecret,
    ) -> Result<(Self, Vec<[u8; 32]>), PacketConstructError> {
        if route.len() >= 10 {
            return Err(PacketConstructError::TooManyHops);
        }
        // Use a recursive algorithm. Base case: the route is empty
        if route.is_empty() {
            let sealed_payload = payload
                .seal(my_isk, destination)
                .map_err(|_| PacketConstructError::MessageTooBig)?;
            // Encrypt for the destination, so that when the destination peels, it receives a PeeledPacket::Receive
            let mut buffer = [0; 21];
            buffer[1..].copy_from_slice(&metadata[..]);
            let (header_outer, our_sk) = box_encrypt(&buffer, destination);

            let shared_sec = our_sk.shared_secret(destination);

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
                            let mut bts = [0; 621];
                            rand::thread_rng().fill_bytes(&mut bts);
                            bts
                        },
                    },
                    onion_body,
                },
                vec![shared_sec],
            ))
        } else {
            let (next_hop, mut shared_secs) =
                RawPacket::new(&route[1..], destination, payload, metadata, my_isk)?;
            let mut buffer = [1; 21];
            buffer[1..].copy_from_slice(route[0].next_fingerprint.as_bytes());
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
                let mut new_header_inner =
                    *array_ref![bytemuck::cast_ref::<_, [u8; 690]>(&next_hop.header), 0, 621];
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

    /// Creates a RawPacket for a message to an anonymous identity, using a ReplyBlock
    pub fn from_reply_block(
        reply_block: &ReplyBlock,
        payload: InnerPacket,
        my_isk: &IdentitySecret,
    ) -> Result<Self, PacketConstructError> {
        Ok(Self {
            header: reply_block.header,
            onion_body: payload
                .seal(my_isk, &reply_block.e2e_dest)
                .map_err(|_| PacketConstructError::MessageTooBig)?,
        })
    }

    /// "Peels off" one layer of the onion, by decryption using the specified secret key.
    pub fn peel(&self, our_sk: &OnionSecret) -> Result<PeeledPacket, PacketPeelError> {
        // First, decode the header
        let (metadata, their_pk) = box_decrypt(&self.header.outer, our_sk)
            .map_err(|_| PacketPeelError::DecryptionError)?;
        assert_eq!(metadata.len(), 21);
        let metadata_marker = metadata[0];
        let shared_sec = our_sk.shared_secret(&their_pk);
        let fingerprint = Fingerprint::from_bytes(array_ref![metadata, 1, 20]);
        // Then, peel the header
        let peeled_header = {
            let header_key = blake3::keyed_hash(b"header__________________________", &shared_sec);
            let mut buffer = [0u8; 690];
            buffer[..621].copy_from_slice(&self.header.inner);
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

        Ok(if metadata == [0; 21] {
            let (inner_pkt, fp) = InnerPacket::open(&peeled_body, our_sk)
                .map_err(|_| PacketPeelError::InnerPacketOpenError)?;
            PeeledPacket::Received {
                from: fp,
                pkt: inner_pkt,
            }
        } else if metadata_marker == 0 {
            let id_bts = array_ref![metadata, 1, 8];
            let id = u64::from_be_bytes(*id_bts);
            PeeledPacket::Garbled {
                id,
                pkt: peeled_body,
            }
        } else {
            PeeledPacket::Forward {
                to: fingerprint,
                pkt: RawPacket {
                    header: bytemuck::cast(peeled_header),
                    onion_body: peeled_body,
                },
            }
        })
    }
}

/// The raw, encrypted header of an Earendil packet.
#[derive(Pod, Clone, Copy, Zeroable, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[repr(C)]
pub struct RawHeader {
    /// Box-encrypted, 21-byte flag (1 byte) + fingerprint OR metadata (20 bytes)
    #[serde(with = "BigArray")]
    pub outer: [u8; 69],
    /// Padding so that header is fixed-size
    #[serde(with = "BigArray")]
    pub inner: [u8; 621],
}

/// A "peeled" Earendil packet.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum PeeledPacket {
    Forward { to: Fingerprint, pkt: RawPacket },
    Received { from: Fingerprint, pkt: InnerPacket },
    Garbled { id: u64, pkt: [u8; 8192] },
}
