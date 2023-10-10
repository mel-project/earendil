use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};

pub mod crypt;

mod inner;
mod raw;
pub use inner::*;
pub use raw::*;

/// An Earendil node fingerprint, uniquely identifying a relay or client.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Ord, Eq, Hash, Serialize, Deserialize)]
pub struct Fingerprint([u8; 20]);

impl Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let b64 = bs58::encode(self.0).into_string();
        write!(f, "{}", b64)
    }
}

impl FromStr for Fingerprint {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bs58::decode(s).into_vec()?;
        if bytes.len() == 20 {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&bytes);
            Ok(Fingerprint(arr))
        } else {
            Err(anyhow::anyhow!("Invalid fingerprint length"))
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
    use crate::crypt::OnionSecret;

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
