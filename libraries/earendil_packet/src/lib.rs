pub mod crypt;
pub mod reply_block;

mod inner;
mod raw;

pub use inner::*;
pub use raw::*;
pub use reply_block::*;

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use earendil_crypt::{AnonRemote, RelayFingerprint, RelayIdentitySecret, RemoteId};

    use crate::crypt::OnionSecret;

    use super::*;

    fn generate_forward_instructions(n: usize) -> Vec<(ForwardInstruction, OnionSecret)> {
        (0..n)
            .map(|_| {
                let our_sk = OnionSecret::generate();
                let this_pubkey = our_sk.public();

                let next_hop = RelayFingerprint::from_bytes(&[10; 32]);
                (
                    ForwardInstruction {
                        this_pubkey,
                        next_hop,
                    },
                    our_sk,
                )
            })
            .collect()
    }

    fn test_packet_route(
        route: &[(ForwardInstruction, OnionSecret)],
    ) -> Result<(), PacketConstructError> {
        let my_isk = RelayIdentitySecret::generate();
        let destination_sk = OnionSecret::generate();
        let destination = destination_sk.public();
        let msg = Message {
            source_dock: 0u32,
            dest_dock: 0u32,
            body: Bytes::copy_from_slice(&[0u8; 100]),
        };

        let forward_instructions: Vec<ForwardInstruction> =
            route.iter().map(|(inst, _)| *inst).collect();
        let is_client = false;

        let (packet, _) = RawPacket::new(
            &forward_instructions,
            &destination,
            is_client,
            InnerPacket::Message(msg.clone()),
            &[0; 32],
            RemoteId::Relay(my_isk.public().fingerprint()),
        )?;

        let mut peeled_packet = packet;
        for (_, our_sk) in route {
            match peeled_packet.peel(our_sk) {
                Ok(PeeledPacket::Relay {
                    next_peeler: _,
                    pkt: next_packet,
                    delay_ms: _delay,
                }) => {
                    peeled_packet = next_packet;
                }
                e => panic!("Expected forward packet, got {:?}", e),
            }
        }

        let final_packet = peeled_packet
            .peel(&destination_sk)
            .expect("Failed to peel packet");
        match final_packet {
            PeeledPacket::Received {
                from: _,
                pkt: received_payload,
            } => {
                let received_msg = if let InnerPacket::Message(bts) = received_payload {
                    bts
                } else {
                    panic!("Expected message, not reply blocks")
                };
                assert_eq!(received_msg, msg);
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

    #[test]
    fn reply_block_five_hops() {
        use crate::reply_block::ReplyBlock;
        use crate::ForwardInstruction;
        use crate::InnerPacket;
        use crate::RawPacket;

        // Generate  identity secrets
        let alice_anon_id = AnonRemote::new();
        let alice_osk = OnionSecret::generate();
        let alice_opk = alice_osk.public();
        // Generate 5-hop route
        let route_with_onion_secrets = generate_forward_instructions(5);
        let route: Vec<ForwardInstruction> = route_with_onion_secrets
            .iter()
            .map(|(inst, _)| *inst)
            .collect();
        let first_peeler = RelayFingerprint::from_bytes(&[10; 32]);

        // Prepare reply block
        let (reply_block, (_, reply_degarbler)) =
            ReplyBlock::new(&route, first_peeler, &alice_opk, 0, alice_anon_id)
                .expect("Failed to create reply block");

        // Prepare message using header from reply block
        let body = "hello world from reply block!";
        let message = Message {
            source_dock: 0u32,
            dest_dock: 0u32,
            body: Bytes::copy_from_slice(body.as_bytes()),
        };
        let packet = RawPacket::new_reply(
            &reply_block,
            InnerPacket::Message(message.clone()),
            &RemoteId::Relay(RelayFingerprint::from_bytes(&rand::random())),
        )
        .expect("Failed to create reply packet");

        // Send the message to alice using the reply block
        let mut peeled_packet = packet;
        for (_, our_sk) in &route_with_onion_secrets {
            match peeled_packet.peel(our_sk).expect("Failed to peel packet") {
                PeeledPacket::Relay {
                    next_peeler: _,
                    pkt: next_packet,
                    delay_ms: _delay,
                } => {
                    peeled_packet = next_packet;
                }
                _ => panic!("Expected forward packet"),
            }
        }
        // At the destination (alice), peel the packet
        let mut peeled_reply = if let PeeledPacket::GarbledReply {
            id: _,
            pkt: peeled_reply,
            client_id: _,
        } = peeled_packet
            .peel(&alice_osk)
            .expect("Failed to peel packet")
        {
            peeled_reply
        } else {
            panic!("Expected receive packet")
        };
        // Degarble the reply block and check the message
        let (inner_packet, _) = reply_degarbler
            .degarble(&mut peeled_reply)
            .expect("Failed to degarble");
        if let InnerPacket::Message(msg) = inner_packet {
            assert_eq!(msg, message);
        } else {
            panic!("Expected InnerPacket::Message");
        }
    }
}
