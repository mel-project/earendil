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
    use earendil_crypt::{Fingerprint, IdentitySecret};

    use crate::crypt::{OnionPublic, OnionSecret};

    use super::*;

    fn generate_forward_instructions(n: usize) -> Vec<(ForwardInstruction, OnionSecret)> {
        (0..n)
            .map(|_| {
                let our_sk = OnionSecret::generate();
                let this_pubkey = our_sk.public();

                let next_fingerprint = Fingerprint::from_bytes(&[10; 20]);
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

    // fn reverse_route(
    //     route: &[ForwardInstruction],
    //     destination: OnionPublic,
    // ) -> Vec<ForwardInstruction> {
    //     let mut reverse_route = Vec::new();
    //     let mut previous = destination;

    //     for instruction in route.into_iter().rev() {
    //         let new_instruction = ForwardInstruction {
    //             this_pubkey: previous,
    //             next_fingerprint: instruction.next_fingerprint,
    //         };
    //         reverse_route.push(new_instruction);
    //         previous = instruction.this_pubkey;
    //     }
    //     eprintln!("reverse_route len: {}", reverse_route.len());
    //     reverse_route
    // }

    fn test_packet_route(
        route: &[(ForwardInstruction, OnionSecret)],
    ) -> Result<(), PacketConstructError> {
        let destination_sk = OnionSecret::generate();
        let destination = destination_sk.public();
        let payload = [0u8; 8192];
        let forward_instructions: Vec<ForwardInstruction> =
            route.iter().map(|(inst, _)| *inst).collect();
        let (packet, _) = RawPacket::new(&forward_instructions, &destination, &payload, &[0; 20])?;

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

    #[test]
    fn reply_block_five_hops() {
        use crate::crypt::OnionSecret;
        use crate::reply_block::ReplyBlock;
        use crate::ForwardInstruction;
        use crate::InnerPacket;
        use crate::RawPacket;

        // Generate  identity secret
        let bob_isk = IdentitySecret::generate();
        let bob_sk = OnionSecret::generate();
        let bob_op = bob_sk.public();

        // Generate 5-hop route
        let route_with_onion_secrets = generate_forward_instructions(5);
        let route: Vec<ForwardInstruction> = route_with_onion_secrets
            .iter()
            .map(|(inst, _)| inst.clone())
            .collect();

        // Prepare reply block
        let (reply_block, (_, rb_degarbler)) =
            ReplyBlock::new(&route).expect("Failed to create reply block");

        // Prepare message using header from reply block
        let message = "hello world from reply block!";
        let inner_pkt = InnerPacket::Message(Bytes::copy_from_slice(message.as_bytes()))
            .seal(&bob_isk, &reply_block.e2e_dest)
            .expect("Could not construct InnerPacket");
        let packet = RawPacket::from_reply_block(&reply_block, &inner_pkt)
            .expect("Failed to create reply packet");

        // Send the message to alice using the reply block
        let mut peeled_packet = packet;
        for (_, our_sk) in &route_with_onion_secrets {
            match peeled_packet.peel(our_sk).expect("Failed to peel packet") {
                PeeledPacket::Forward(_, next_packet) => {
                    peeled_packet = next_packet;
                }
                _ => panic!("Expected forward packet"),
            }
        }
        // At the destination (alice), peel the packet
        let peeled_reply = if let PeeledPacket::Receive(peeled_reply) = peeled_packet
            .peel(&rb_degarbler.my_onion_secret)
            .expect("Failed to peel packet")
        {
            peeled_reply
        } else {
            panic!("Expected receive packet")
        };
        // Degarble the reply block and check the message
        let (inner_packet, _) = rb_degarbler
            .degarble(peeled_reply)
            .expect("Failed to degarble");
        if let InnerPacket::Message(msg_bts) = inner_packet {
            let msg =
                String::from_utf8(msg_bts.to_vec()).expect("Failed to convert message to string");
            assert_eq!(msg, message);
        } else {
            panic!("Expected InnerPacket::Message");
        }
    }
}
