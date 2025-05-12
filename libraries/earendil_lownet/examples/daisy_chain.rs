use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use async_io::Timer;
use bytes::Bytes;
use earendil_crypt::RelayIdentitySecret;
use earendil_lownet::{
    Datagram, InLinkConfig, LowNet, LowNetConfig, NodeAddr, NodeIdentity, ObfsConfig, OutLinkConfig,
};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().compact())
        .with(
            EnvFilter::builder()
                .with_default_directive("earendil".parse().unwrap())
                .from_env_lossy(),
        )
        .init();
    smolscale::block_on(async {
        let relays = build_daisy_chain(5).await;
        Timer::after(Duration::from_secs(10)).await;

        // Send a message from the first relay to the last relay
        let source = relays.first().unwrap();
        let destination = relays.last().unwrap();

        let dest_addr = NodeAddr {
            relay: match destination.topology().await.identity() {
                NodeIdentity::Relay(rel) => rel.public().fingerprint(),
                _ => unreachable!(),
            },
            client_id: 0,
        };

        // Create and send a test datagram
        let datagram = Datagram {
            ttl: 10,
            dest_addr,
            payload: Bytes::from("Hello from the first relay!"),
        };

        let start = Instant::now();
        println!("Sending message from first relay to last relay in the chain");
        source.send(datagram).await;

        // Wait for the message to arrive
        let received = destination.recv().await;
        println!(
            "Last relay received: {:?} in {:?}",
            String::from_utf8_lossy(&received.payload),
            start.elapsed()
        );
    });
}

async fn build_daisy_chain(num_relays: usize) -> Vec<LowNet> {
    println!("Building a daisy chain of {} relays", num_relays);

    let mut relays = Vec::with_capacity(num_relays);
    let mut private_keys = Vec::with_capacity(num_relays);

    // Create relay identity keys
    for i in 0..num_relays {
        let private_key = RelayIdentitySecret::generate();
        println!(
            "Relay {} fingerprint: {}",
            i,
            private_key.public().fingerprint()
        );
        private_keys.push(private_key);
    }

    // Create the first relay (only has an incoming link)
    let first_relay_config = LowNetConfig {
        identity: NodeIdentity::Relay(private_keys[0]),
        in_links: vec![InLinkConfig {
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9000),
            obfs: ObfsConfig::None,
        }],
        out_links: vec![],
    };

    relays.push(LowNet::new(first_relay_config));
    println!("Created first relay");

    // Create middle relays (have both incoming and outgoing links)
    for i in 1..num_relays - 1 {
        let relay_config = LowNetConfig {
            identity: NodeIdentity::Relay(private_keys[i]),
            in_links: vec![InLinkConfig {
                listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9000 + i as u16),
                obfs: ObfsConfig::None,
            }],
            out_links: vec![OutLinkConfig {
                connect: format!("127.0.0.1:{}", 9000 + i as u16 - 1),
                fingerprint: private_keys[i - 1].public().fingerprint(),
                obfs: ObfsConfig::None,
            }],
        };

        relays.push(LowNet::new(relay_config));
        println!("Created relay {}", i);
    }

    // Create the last relay (only has an outgoing link)
    if num_relays > 1 {
        let last_index = num_relays - 1;
        let last_relay_config = LowNetConfig {
            identity: NodeIdentity::Relay(private_keys[last_index]),
            in_links: vec![],
            out_links: vec![OutLinkConfig {
                connect: format!("127.0.0.1:{}", 9000 + last_index as u16 - 1),
                fingerprint: private_keys[last_index - 1].public().fingerprint(),
                obfs: ObfsConfig::None,
            }],
        };

        relays.push(LowNet::new(last_relay_config));
        println!("Created last relay");
    }

    // Allow time for connections to establish
    println!("Waiting for connections to establish...");
    async_io::Timer::after(Duration::from_secs(1)).await;

    relays
}
