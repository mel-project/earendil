use std::time::Duration;

use anyhow::Context;
use bytes::Bytes;
use earendil::socket::Socket;
use earendil_crypt::HavenIdentitySecret;
use smol::Timer;
use smol_timeout::TimeoutExt;
use tracing_test::traced_test;

mod helpers;

#[test]
#[traced_test]
fn n2r() {
    helpers::env_vars();

    let seed = helpers::gen_seed("n2r");
    let (mut relays, _clients) = helpers::spawn_network(16, 0, Some(seed)).unwrap();
    smolscale::block_on(async move {
        let alice = relays.pop().unwrap();
        let alice_skt = Socket::bind_n2r_client(&alice, None).await.unwrap();
        let bob = relays.pop().unwrap();
        let bob_skt = Socket::bind_n2r_relay(&bob, None).await.unwrap();

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
#[traced_test]
fn haven() {
    helpers::env_vars();

    let seed = helpers::gen_seed("haven");
    let (mut relays, mut clients) = helpers::spawn_network(2, 4, Some(seed)).unwrap();

    smolscale::block_on(async move {
        helpers::sleep(5).await;
        let alice = clients.pop().unwrap();

        let alice_anon_isk = HavenIdentitySecret::generate();
        let alice_skt = Socket::bind_haven(&alice, alice_anon_isk, None, None)
            .await
            .unwrap();
        let alice_anon_fp = alice_skt.local_endpoint();

        let bob = relays.pop().unwrap();
        let bob_haven_isk = HavenIdentitySecret::generate();
        let bob_skt = Socket::bind_haven(
            &bob,
            bob_haven_isk,
            None,
            Some(
                relays
                    .last()
                    .unwrap()
                    .identity()
                    .unwrap()
                    .public()
                    .fingerprint(),
            ),
        )
        .await
        .unwrap();
        let bob_haven_fp = bob_skt.local_endpoint();

        let to_bob = b"hello bobert";
        let to_alice = b"hey there, allison";

        helpers::sleep(5).await;

        alice_skt
            .send_to(Bytes::copy_from_slice(to_bob), bob_haven_fp)
            .await
            .unwrap();

        let (from_alice, _) = bob_skt
            .recv_from()
            .timeout(Duration::from_secs(10))
            .await
            .unwrap()
            .unwrap();
        Timer::after(Duration::from_millis(100)).await;
        assert_eq!(from_alice.as_ref(), to_bob);

        bob_skt
            .send_to(Bytes::copy_from_slice(to_alice), alice_anon_fp)
            .timeout(Duration::from_secs(10))
            .await
            .unwrap()
            .unwrap();

        let (from_bob, _) = alice_skt
            .recv_from()
            .timeout(Duration::from_secs(20))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(from_bob.as_ref(), to_alice);
    });
}
