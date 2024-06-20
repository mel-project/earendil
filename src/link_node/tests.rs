use std::collections::BTreeMap;

use earendil_crypt::RelayIdentitySecret;
use melstructs::NetID;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::{
    config::{InRouteConfig, ObfsConfig, OutRouteConfig, PriceConfig},
    Dummy, LinkConfig, LinkNode,
};

pub async fn get_two_connected_relays() -> (LinkNode, LinkNode) {
    let idsk1 = RelayIdentitySecret::generate();
    let mut in_1 = BTreeMap::new();
    in_1.insert(
        "1".to_owned(),
        InRouteConfig {
            listen: "127.0.0.1:30000".parse().unwrap(),
            obfs: ObfsConfig::None,
            price_config: PriceConfig {
                inbound_price: 5,
                inbound_debt_limit: 500,
                outbound_max_price: 10,
            },
        },
    );

    let idsk2 = RelayIdentitySecret::generate();
    let mut in_2 = BTreeMap::new();
    in_2.insert(
        "2".to_owned(),
        InRouteConfig {
            listen: "127.0.0.1:30001".parse().unwrap(),
            obfs: ObfsConfig::None,
            price_config: PriceConfig {
                inbound_price: 5,
                inbound_debt_limit: 20,
                outbound_max_price: 10,
            },
        },
    );
    let mut out_2 = BTreeMap::new();
    out_2.insert(
        "1".to_owned(),
        OutRouteConfig {
            connect: "127.0.0.1:30000".parse().unwrap(),
            fingerprint: idsk1.public().fingerprint(),
            obfs: ObfsConfig::None,
            price_config: PriceConfig {
                inbound_price: 5,
                inbound_debt_limit: 20,
                outbound_max_price: 10,
            },
        },
    );

    let node1 = LinkNode::new(
        LinkConfig {
            relay_config: Some((idsk1, in_1)),
            out_routes: BTreeMap::new(),
            db_path: {
                let mut path = tempfile::tempdir().unwrap().into_path();
                path.push(idsk1.public().fingerprint().to_string());
                path
            },
            payment_systems: vec![Box::new(Dummy::new())],
        },
        melprot::Client::autoconnect(NetID::Mainnet).await.unwrap(),
    );

    let node2 = LinkNode::new(
        LinkConfig {
            relay_config: Some((idsk2, in_2)),
            out_routes: out_2,
            db_path: {
                let mut path = tempfile::tempdir().unwrap().into_path();
                path.push(idsk2.public().fingerprint().to_string());
                path
            },
            payment_systems: vec![Box::new(Dummy::new())],
        },
        melprot::Client::autoconnect(NetID::Mainnet).await.unwrap(),
    );

    (node1, node2)
}

pub fn init_tracing() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().compact())
        .with(
            EnvFilter::builder()
                .with_default_directive("earendil=debug".parse()?)
                .from_env_lossy(),
        )
        .init();
    Ok(())
}

pub async fn get_connected_relay_client() -> (LinkNode, LinkNode) {
    let idsk1 = RelayIdentitySecret::generate();
    let mut in_1 = BTreeMap::new();
    in_1.insert(
        "1".to_owned(),
        InRouteConfig {
            listen: "127.0.0.1:30000".parse().unwrap(),
            obfs: ObfsConfig::None,
            price_config: PriceConfig {
                inbound_price: 5,
                inbound_debt_limit: 20,
                outbound_max_price: 10,
            },
        },
    );

    let mut out_2 = BTreeMap::new();
    out_2.insert(
        "1".to_owned(),
        OutRouteConfig {
            connect: "127.0.0.1:30000".parse().unwrap(),
            fingerprint: idsk1.public().fingerprint(),
            obfs: ObfsConfig::None,
            price_config: PriceConfig {
                inbound_price: 5,
                inbound_debt_limit: 20,
                outbound_max_price: 10,
            },
        },
    );

    let relay = LinkNode::new(
        LinkConfig {
            relay_config: Some((idsk1, in_1)),
            out_routes: BTreeMap::new(),
            db_path: {
                let mut path = tempfile::tempdir().unwrap().into_path();
                path.push(idsk1.public().fingerprint().to_string());
                path
            },
            payment_systems: vec![Box::new(Dummy::new())],
        },
        melprot::Client::autoconnect(NetID::Mainnet).await.unwrap(),
    );

    let client = LinkNode::new(
        LinkConfig {
            relay_config: None,
            out_routes: out_2,
            db_path: {
                let mut path = tempfile::tempdir().unwrap().into_path();
                path.push(
                    RelayIdentitySecret::generate()
                        .public()
                        .fingerprint()
                        .to_string(),
                );
                path
            },
            payment_systems: vec![Box::new(Dummy::new())],
        },
        melprot::Client::autoconnect(NetID::Mainnet).await.unwrap(),
    );

    (relay, client)
}

pub async fn get_four_connected_relays() -> (LinkNode, LinkNode, LinkNode, LinkNode) {
    let idsk1 = RelayIdentitySecret::generate();
    let mut in_1 = BTreeMap::new();
    in_1.insert(
        "1".to_owned(),
        InRouteConfig {
            listen: "127.0.0.1:30000".parse().unwrap(),
            obfs: ObfsConfig::None,
            price_config: PriceConfig {
                inbound_price: 5,
                inbound_debt_limit: 500,
                outbound_max_price: 10,
            },
        },
    );

    let idsk2 = RelayIdentitySecret::generate();
    let mut in_2 = BTreeMap::new();
    in_2.insert(
        "2".to_owned(),
        InRouteConfig {
            listen: "127.0.0.1:30001".parse().unwrap(),
            obfs: ObfsConfig::None,
            price_config: PriceConfig {
                inbound_price: 5,
                inbound_debt_limit: 500,
                outbound_max_price: 10,
            },
        },
    );
    let mut out_2 = BTreeMap::new();
    out_2.insert(
        "1".to_owned(),
        OutRouteConfig {
            connect: "127.0.0.1:30000".parse().unwrap(),
            fingerprint: idsk1.public().fingerprint(),
            obfs: ObfsConfig::None,
            price_config: PriceConfig {
                inbound_price: 5,
                inbound_debt_limit: 500,
                outbound_max_price: 10,
            },
        },
    );

    let idsk3 = RelayIdentitySecret::generate();
    let mut in_3 = BTreeMap::new();
    in_3.insert(
        "1".to_owned(),
        InRouteConfig {
            listen: "127.0.0.1:30002".parse().unwrap(),
            obfs: ObfsConfig::None,
            price_config: PriceConfig {
                inbound_price: 5,
                inbound_debt_limit: 500,
                outbound_max_price: 10,
            },
        },
    );
    let mut out_3 = BTreeMap::new();
    out_3.insert(
        "1".to_owned(),
        OutRouteConfig {
            connect: "127.0.0.1:30001".parse().unwrap(),
            fingerprint: idsk1.public().fingerprint(),
            obfs: ObfsConfig::None,
            price_config: PriceConfig {
                inbound_price: 5,
                inbound_debt_limit: 500,
                outbound_max_price: 10,
            },
        },
    );
    let idsk4 = RelayIdentitySecret::generate();
    let mut in_4 = BTreeMap::new();
    in_4.insert(
        "2".to_owned(),
        InRouteConfig {
            listen: "127.0.0.1:30003".parse().unwrap(),
            obfs: ObfsConfig::None,
            price_config: PriceConfig {
                inbound_price: 5,
                inbound_debt_limit: 500,
                outbound_max_price: 10,
            },
        },
    );
    let mut out_4 = BTreeMap::new();
    out_4.insert(
        "1".to_owned(),
        OutRouteConfig {
            connect: "127.0.0.1:30002".parse().unwrap(),
            fingerprint: idsk1.public().fingerprint(),
            obfs: ObfsConfig::None,
            price_config: PriceConfig {
                inbound_price: 5,
                inbound_debt_limit: 500,
                outbound_max_price: 10,
            },
        },
    );

    let node1 = LinkNode::new(
        LinkConfig {
            relay_config: Some((idsk1, in_1)),
            out_routes: BTreeMap::new(),
            db_path: {
                let mut path = tempfile::tempdir().unwrap().into_path();
                path.push(idsk1.public().fingerprint().to_string());
                path
            },
            payment_systems: vec![Box::new(Dummy::new())],
        },
        melprot::Client::autoconnect(NetID::Mainnet).await.unwrap(),
    );
    let node2 = LinkNode::new(
        LinkConfig {
            relay_config: Some((idsk2, in_2)),
            out_routes: out_2,
            db_path: {
                let mut path = tempfile::tempdir().unwrap().into_path();
                path.push(idsk2.public().fingerprint().to_string());
                path
            },
            payment_systems: vec![Box::new(Dummy::new())],
        },
        melprot::Client::autoconnect(NetID::Mainnet).await.unwrap(),
    );
    let node3 = LinkNode::new(
        LinkConfig {
            relay_config: Some((idsk3, in_3)),
            out_routes: out_3,
            db_path: {
                let mut path = tempfile::tempdir().unwrap().into_path();
                path.push(idsk3.public().fingerprint().to_string());
                path
            },
            payment_systems: vec![Box::new(Dummy::new())],
        },
        melprot::Client::autoconnect(NetID::Mainnet).await.unwrap(),
    );
    let node4 = LinkNode::new(
        LinkConfig {
            relay_config: Some((idsk4, in_4)),
            out_routes: out_4,
            db_path: {
                let mut path = tempfile::tempdir().unwrap().into_path();
                path.push(idsk4.public().fingerprint().to_string());
                path
            },
            payment_systems: vec![Box::new(Dummy::new())],
        },
        melprot::Client::autoconnect(NetID::Mainnet).await.unwrap(),
    );

    (node1, node2, node3, node4)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::{link_node::types::NeighborId, IncomingMsg};

    use super::*;
    use bytes::Bytes;
    use earendil_crypt::AnonEndpoint;
    use earendil_packet::{InnerPacket, Message, RawBody};

    #[test]
    fn two_relays_one_forward_pkt() {
        let _ = init_tracing();

        let pkt = InnerPacket::Message(Message {
            relay_dock: 123,
            body: Bytes::from_static(b"lol"),
        });
        smol::block_on(async {
            let (node1, node2) = get_two_connected_relays().await;
            smol::Timer::after(Duration::from_secs(3)).await;
            node2
                .send_forward(
                    pkt.clone(),
                    AnonEndpoint::random(),
                    node1
                        .ctx
                        .cfg
                        .relay_config
                        .as_ref()
                        .unwrap()
                        .0
                        .public()
                        .fingerprint(), // we know node1 is a relay
                )
                .await
                .unwrap();
            match node1.recv().await {
                IncomingMsg::Forward { from: _, body } => {
                    assert_eq!(body, pkt);
                }
                IncomingMsg::Backward { rb_id: _, body: _ } => panic!("not supposed to happen"),
            }
        });
    }

    #[test]
    fn two_relays_one_backward_pkt() {
        let _ = init_tracing();

        smol::block_on(async {
            let (node1, node2) = get_two_connected_relays().await;
            smol::Timer::after(Duration::from_secs(3)).await;
            let (surb_1to2, surb_id, degarbler) = node2
                .surb_from(
                    AnonEndpoint::random(),
                    node1
                        .ctx
                        .cfg
                        .relay_config
                        .clone()
                        .unwrap()
                        .0
                        .public()
                        .fingerprint(),
                )
                .unwrap(); // we know that node1 is a relay
            println!("got surb");
            let msg_relay_dock = 123;
            let msg_body = Bytes::from_static(b"lol");
            node1
                .send_backwards(
                    surb_1to2,
                    Message {
                        relay_dock: msg_relay_dock,
                        body: msg_body.clone(),
                    },
                )
                .await
                .unwrap();
            println!("msg sent");
            match node2.recv().await {
                IncomingMsg::Forward { from: _, body: _ } => panic!("not supposed to happen"),
                IncomingMsg::Backward { rb_id, body } => {
                    assert_eq!(rb_id, surb_id);
                    let mut body: RawBody = *bytemuck::try_from_bytes(&body).unwrap();
                    let (inner_pkt, _) = degarbler.degarble(&mut body).unwrap();
                    match inner_pkt {
                        InnerPacket::Message(Message { relay_dock, body }) => {
                            assert_eq!(msg_body, body);
                            assert_eq!(msg_relay_dock, relay_dock);
                            println!("YAY SUCCESS")
                        }
                        InnerPacket::Surbs(_) => todo!(),
                    }
                }
            }
        })
    }

    #[test]
    fn client_relay_one_forward_pkt() {
        let _ = init_tracing();

        let pkt = InnerPacket::Message(Message {
            relay_dock: 123,
            body: Bytes::from_static(b"lol"),
        });

        smol::block_on(async {
            let (relay_node, client_node) = get_connected_relay_client().await;
            smol::Timer::after(Duration::from_secs(3)).await;
            for i in 0..10 {
                println!("i={i}");
                match client_node
                    .send_forward(
                        pkt.clone(),
                        AnonEndpoint::random(),
                        relay_node
                            .ctx
                            .cfg
                            .relay_config
                            .clone()
                            .unwrap()
                            .0
                            .public()
                            .fingerprint(), // we know node1 is a relay
                    )
                    .await
                {
                    Ok(_) => println!("client --> relay LinkMsg sent"),
                    Err(e) => println!("ERR sending client --> relay LinkMsfg: {e}"),
                }
                match relay_node.recv().await {
                    IncomingMsg::Forward { from: _, body } => {
                        assert_eq!(body, pkt);
                    }
                    IncomingMsg::Backward { rb_id: _, body: _ } => panic!("not supposed to happen"),
                }
            }
        });
    }

    #[test]
    fn client_relay_one_backward_pkt() {
        let _ = init_tracing();

        smol::block_on(async {
            let (relay_node, client_node) = get_connected_relay_client().await;
            smol::Timer::after(Duration::from_secs(3)).await;
            println!(
                "relay_node fp = {}",
                relay_node
                    .ctx
                    .cfg
                    .relay_config
                    .clone()
                    .unwrap()
                    .0
                    .public()
                    .fingerprint(),
            );
            let (surb_1to2, surb_id, degarbler) = client_node
                .surb_from(
                    AnonEndpoint::random(),
                    relay_node
                        .ctx
                        .cfg
                        .relay_config
                        .clone()
                        .unwrap()
                        .0
                        .public()
                        .fingerprint(),
                )
                .unwrap(); // we know that node1 is a relay
            println!("got surb");
            let msg_relay_dock = 123;
            let msg_body = Bytes::from_static(b"lol");
            relay_node
                .send_backwards(
                    surb_1to2,
                    Message {
                        relay_dock: msg_relay_dock,
                        body: msg_body.clone(),
                    },
                )
                .await
                .unwrap();
            println!("msg sent");
            match client_node.recv().await {
                IncomingMsg::Forward { from: _, body: _ } => panic!("not supposed to happen"),
                IncomingMsg::Backward { rb_id, body } => {
                    assert_eq!(rb_id, surb_id);
                    let mut body: RawBody = *bytemuck::try_from_bytes(&body).unwrap();
                    let (inner_pkt, _) = degarbler.degarble(&mut body).unwrap();
                    match inner_pkt {
                        InnerPacket::Message(Message { relay_dock, body }) => {
                            assert_eq!(msg_body, body);
                            assert_eq!(msg_relay_dock, relay_dock);
                            println!("YAY SUCCESS")
                        }
                        InnerPacket::Surbs(_) => todo!(),
                    }
                }
            }
        })
    }

    #[test]
    fn four_relays_forward_pkt() {
        let _ = init_tracing();

        let pkt = InnerPacket::Message(Message {
            relay_dock: 123,
            body: Bytes::from_static(b"lol"),
        });
        smol::block_on(async {
            let (node1, _node2, _node3, node4) = get_four_connected_relays().await;
            smol::Timer::after(Duration::from_secs(5)).await;
            node4
                .send_forward(
                    pkt.clone(),
                    AnonEndpoint::random(),
                    node1
                        .ctx
                        .cfg
                        .relay_config
                        .clone()
                        .unwrap()
                        .0
                        .public()
                        .fingerprint(), // we know node1 is a relay
                )
                .await
                .unwrap();
            match node1.recv().await {
                IncomingMsg::Forward { from: _, body } => {
                    assert_eq!(body, pkt);
                }
                IncomingMsg::Backward { rb_id: _, body: _ } => panic!("not supposed to happen"),
            }
        });
    }

    #[test]
    fn two_relays_one_chat() {
        let _ = init_tracing();

        smol::block_on(async {
            let (node1, node2) = get_two_connected_relays().await;
            smol::Timer::after(Duration::from_secs(3)).await;
            let chat_msg = "hi test".to_string();
            node2
                .send_chat(
                    NeighborId::Relay(
                        node1
                            .ctx
                            .cfg
                            .relay_config
                            .clone()
                            .unwrap()
                            .0
                            .public()
                            .fingerprint(),
                    ), // we know node1 is a relay
                    chat_msg.clone(),
                )
                .await
                .unwrap();

            smol::Timer::after(Duration::from_secs(1)).await;

            let node1_chat_hist = node1
                .get_chat_history(NeighborId::Relay(
                    node2
                        .ctx
                        .cfg
                        .relay_config
                        .clone()
                        .unwrap()
                        .0
                        .public()
                        .fingerprint(),
                ))
                .await
                .unwrap();

            assert_eq!(node1_chat_hist[0].text, chat_msg);
        });
    }
}
