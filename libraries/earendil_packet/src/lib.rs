use std::{fmt::Display, str::FromStr};

use arrayref::array_ref;

use base64::Engine;
use bytemuck::{Pod, Zeroable};
use crypt::{box_decrypt, box_encrypt, AeadError, OnionPublic, OnionSecret};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypt::stream_dencrypt;

pub mod crypt;

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
#[derive(Pod, Clone, Copy, Zeroable, Debug)]
#[repr(C)]
pub struct RawHeader {
    /// Box-encrypted, 20-byte fingerprint
    pub outer: [u8; 68],
    /// Padding so that header is fixed-size
    pub inner: [u8; 612],
}

/// A "peeled" Earendil packet.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum PeeledPacket {
    Forward(Fingerprint, RawPacket),
    Receive([u8; 8192]),
}

/// An Earendil node fingerprint, uniquely identifying a relay or client.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Ord, Eq, Hash, Serialize, Deserialize)]
pub struct Fingerprint([u8; 20]);

impl Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.0);
        write!(f, "{}", b64)
    }
}

impl FromStr for Fingerprint {
    type Err = Box<dyn std::error::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)?;
        if bytes.len() == 20 {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&bytes);
            Ok(Fingerprint(arr))
        } else {
            Err("Invalid fingerprint length".into())
        }
    }
}

impl Fingerprint {
    /// Convert from bytes representation
    pub fn from_bytes(b: &[u8; 20]) -> Self {
        Self(*b)
    }

    /// View as bytes representation
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_forward_instructions(n: usize) -> Vec<(ForwardInstruction, OnionSecret)> {
        (0..n)
            .map(|_| {
                let our_sk = OnionSecret::generate();
                let this_pubkey = our_sk.public();

                let next_fingerprint = Fingerprint([10; 20]);
                (
                    ForwardInstruction {
                        this_pubkey,
                        next_fingerprint,
                    },
                    our_sk,
                )
            })
            .collect()
    }

    fn test_packet_route(
        route: &[(ForwardInstruction, OnionSecret)],
    ) -> Result<(), PacketConstructError> {
        let destination_sk = OnionSecret::generate();
        let destination = destination_sk.public();
        let payload = [0u8; 8192];
        let forward_instructions: Vec<ForwardInstruction> =
            route.iter().map(|(inst, _)| *inst).collect();
        let packet = RawPacket::new(&forward_instructions, &destination, &payload)?;

        let mut peeled_packet = packet;
        for (_, our_sk) in route {
            match peeled_packet.peel(our_sk) {
                Ok(PeeledPacket::Forward(_, next_packet)) => {
                    peeled_packet = next_packet;
                }
                e => panic!("Expected forward packet, got {:?}", e),
            }
        }

        let final_packet = peeled_packet
            .peel(&destination_sk)
            .expect("Failed to peel packet");
        match final_packet {
            PeeledPacket::Receive(received_payload) => {
                assert_eq!(payload[..5], received_payload[..5]);
                Ok(())
            }
            _ => panic!("Expected receive packet"),
        }
    }

    #[test]
    fn one_hop() {
        let route: Vec<(ForwardInstruction, OnionSecret)> = Vec::new();
        test_packet_route(&route).expect("One-hop test failed");
    }

    #[test]
    fn five_hops() {
        let route = generate_forward_instructions(5);
        test_packet_route(&route).expect("Five-hops test failed");
    }

    #[test]
    fn nine_hops() {
        let route = generate_forward_instructions(9);
        test_packet_route(&route).expect("Ten-hops test failed");
    }

    #[test]
    fn ten_hops_fail() {
        let route = generate_forward_instructions(10);
        match test_packet_route(&route) {
            Err(PacketConstructError::TooManyHops) => {} // expected error
            _ => panic!("Expected TooManyHops error"),
        }
    }
}
