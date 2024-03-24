use std::time::Duration;

use anyhow::Context;
use bytes::Bytes;

use earendil::{HavenConnection, HavenEndpoint, HavenListener, N2rClientSocket, N2rRelaySocket};
use earendil_crypt::{AnonEndpoint, HavenIdentitySecret};

use smol::{future::FutureExt as _, Timer};
use smol_timeout::TimeoutExt;
use tracing_test::traced_test;

mod helpers;

#[test]
#[traced_test]
fn n2r() {
    helpers::init_logs();

    let seed = helpers::gen_seed("n2r");
    let (mut relays, _clients) = helpers::spawn_network(5, 0, Some(seed)).unwrap();
    smolscale::block_on(async move {
        let alice = relays.pop().unwrap();
        let alice_skt = N2rClientSocket::bind(alice.ctx(), AnonEndpoint::new()).unwrap();
        let bob = relays.pop().unwrap();
        let bob_skt = N2rRelaySocket::bind(bob.ctx(), None).unwrap();

        helpers::sleep(10).await;

        println!("{}", alice.control_client().graph_dump(true).await.unwrap());
        dbg!(bob_skt.local_endpoint());

        let alice_msg = Bytes::from_static("in Wonderland rn, wya??".as_bytes());

        alice_skt
            .send_to(alice_msg.clone(), bob_skt.local_endpoint())
            .await
            .context("alice sending failed!")
            .unwrap();

        let (body, ep) = bob_skt
            .recv_from()
            .timeout(Duration::from_secs(10))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(body, alice_msg);
        assert_eq!(ep, alice_skt.local_endpoint());

        let bob_msg = Bytes::from_static("Hello, dear Alice!".as_bytes());
        bob_skt
            .send_to(bob_msg.clone(), alice_skt.local_endpoint())
            .await
            .context("bob sending failed!")
            .unwrap();
        let (body, ep) = alice_skt
            .recv_from()
            .timeout(Duration::from_secs(10))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(body, bob_msg);
        assert_eq!(ep, bob_skt.local_endpoint());
    });
}

#[test]
fn haven() {
    helpers::init_logs();

    let seed = helpers::gen_seed("haven");
    let (mut relays, mut clients) = helpers::spawn_network(2, 4, Some(seed)).unwrap();

    smolscale::block_on(async move {
        helpers::sleep(15).await;

        // tracing::debug!("there are {} relays", relays.len());

        // for relay in relays.iter() {
        //     tracing::debug!("GONNA PRINT");
        //     let graph = relay.control_client().graph_dump(false).await.unwrap();
        //     tracing::debug!("{graph}");
        // }

        // bob
        let bob = relays.pop().unwrap();
        let bob_haven_id = HavenIdentitySecret::generate();
        let bob_haven_port = 1234;
        let rendezvous = relays
            .last()
            .unwrap()
            .identity()
            .unwrap()
            .public()
            .fingerprint();
        let bob_listener =
            HavenListener::bind(&bob.ctx(), bob_haven_id, bob_haven_port, rendezvous)
                .await
                .unwrap();
        eprintln!("BOB BOUND");

        let to_alice = b"hey there, allison";
        let to_bob = b"hello bobert";

        let bob_process = async {
            let bob_conn = bob_listener.accept().await.unwrap();
            bob_conn.send(to_alice).await.unwrap();
            let from_alice = bob_conn.recv().await.unwrap();
            assert_eq!(to_bob, from_alice.as_ref());
        };
        let alice_process = async {
            smol::Timer::after(Duration::from_secs(5)).await;
            let alice = clients.pop().unwrap();
            let alice_conn = HavenConnection::connect(
                &alice.ctx(),
                HavenEndpoint::new(bob_haven_id.public().fingerprint(), bob_haven_port),
            )
            .await
            .unwrap();
            alice_conn.send(to_bob).await.unwrap();
            let from_bob = alice_conn.recv().await.unwrap();
            assert_eq!(from_bob.as_ref(), to_alice);
        };

        bob_process.race(alice_process).await
    });
}
