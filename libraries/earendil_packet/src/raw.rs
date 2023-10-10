use arrayref::array_ref;
use bytemuck::{Pod, Zeroable};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;

use crate::{
    crypt::{box_decrypt, box_encrypt, stream_dencrypt, AeadError, OnionPublic, OnionSecret},
    Fingerprint,
};

/// A raw, on-the-wire Earendil packet.
#[repr(C)]
#[derive(Pod, Clone, Copy, Zeroable, Debug)]
pub struct RawPacket {
    pub header: RawHeader,
    pub onion_body: [u8; 8192],
}

/// An instruction for forwarding one layer of the onion.
#[derive(Clone, Copy)]
pub struct ForwardInstruction {
    /// The DH public key of this hop
    pub this_pubkey: OnionPublic,
    /// The unique fingerprint of the next hop
    pub next_fingerprint: Fingerprint,
}

#[derive(Error, Debug)]
pub enum PacketConstructError {
    #[error("route contains too many hops")]
    TooManyHops,
}

impl RawPacket {
    /// Creates a new RawPacket, given a payload and the series of relays that the packet is supposed to pass through.
    pub fn new(
        route: &[ForwardInstruction],
        destination: &OnionPublic,
        payload: &[u8; 8192],
    ) -> Result<Self, PacketConstructError> {
        if route.len() >= 10 {
            return Err(PacketConstructError::TooManyHops);
        }
        // Use a recursive algorithm. Base case: the route is empty
        if route.is_empty() {
            // Encrypt for the destination, so that when the destination peels, it receives a PeeledPacket::Receive
            let (header_outer, our_sk) = box_encrypt(&[0; 20], destination);

            let shared_sec = our_sk.shared_secret(destination);

            let onion_body = {
                let body_key = blake3::keyed_hash(b"body____________________________", &shared_sec);
                let mut new = *payload;
                stream_dencrypt(body_key.as_bytes(), &[0; 12], &mut new);
                new
            };
            Ok(Self {
                header: RawHeader {
                    outer: header_outer.try_into().unwrap(),
                    inner: {
                        // We fill with garbage, since none of this will get read
                        let mut bts = [0; 612];
                        rand::thread_rng().fill_bytes(&mut bts);
                        bts
                    },
                },
                onion_body,
            })
        } else {
            let next_hop = RawPacket::new(&route[1..], destination, payload)?;
            let (header_outer, our_sk) =
                box_encrypt(&route[0].next_fingerprint.0, &route[0].this_pubkey);
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
                // Shift the first 680-68 bytes of the next-hop header backwards by 68 bytes and encrypt.
                // This drops the last 68 bytes, but we know that that cannot possibly include any useful info because of the 10-hop limit.
                let mut new_header_inner =
                    *array_ref![bytemuck::cast_ref::<_, [u8; 680]>(&next_hop.header), 0, 612];
                stream_dencrypt(header_key.as_bytes(), &[0; 12], &mut new_header_inner);
                new_header_inner
            };
            Ok(Self {
                header: RawHeader {
                    outer: header_outer.try_into().unwrap(),
                    inner: header_inner,
                },
                onion_body,
            })
        }
    }

    /// "Peels off" one layer of the onion, by decryption using the specified secret key.
    pub fn peel(&self, our_sk: &OnionSecret) -> Result<PeeledPacket, AeadError> {
        // First, decode the header
        let (fingerprint, their_pk) = box_decrypt(&self.header.outer, our_sk)?;
        assert_eq!(fingerprint.len(), 20);
        let shared_sec = our_sk.shared_secret(&their_pk);
        let fingerprint = Fingerprint(*array_ref![fingerprint, 0, 20]);
        // Then, peel the header
        let peeled_header = {
            let header_key = blake3::keyed_hash(b"header__________________________", &shared_sec);
            let mut buffer = [0u8; 680];
            buffer[..612].copy_from_slice(&self.header.inner);
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
        Ok(if fingerprint.0 == [0; 20] {
            PeeledPacket::Receive(peeled_body)
        } else {
            PeeledPacket::Forward(
                fingerprint,
                RawPacket {
                    header: bytemuck::cast(peeled_header),
                    onion_body: peeled_body,
                },
            )
        })
    }
}

/// The raw, encrypted header of an Earendil packet.
#[derive(Pod, Clone, Copy, Zeroable, Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct RawHeader {
    /// Box-encrypted, 20-byte fingerprint
    #[serde(with = "BigArray")]
    pub outer: [u8; 68],
    /// Padding so that header is fixed-size
    #[serde(with = "BigArray")]
    pub inner: [u8; 612],
}

/// A "peeled" Earendil packet.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum PeeledPacket {
    Forward(Fingerprint, RawPacket),
    Receive([u8; 8192]),
}
