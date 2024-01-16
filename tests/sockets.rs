use std::{env, fmt::Alignment, time::Duration};

use anyhow::Context;
use bytes::Bytes;
use earendil::{config::ConfigFile, daemon::Daemon, socket::Socket};
use earendil_crypt::IdentitySecret;
use once_cell::sync::Lazy;
use smol::Timer;
use smol_timeout::TimeoutExt;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod helpers;

static ALICE_DAEMON: Lazy<Daemon> =
    Lazy::new(|| daemon_from_yaml(include_str!("test-cfgs/sockets/alice-cfg.yaml")));
static BOB_DAEMON: Lazy<Daemon> =
    Lazy::new(|| daemon_from_yaml(include_str!("test-cfgs/sockets/bob-cfg.yaml")));
static CHARLIE_DAEMON: Lazy<Daemon> =
    Lazy::new(|| daemon_from_yaml(include_str!("test-cfgs/sockets/charlie-cfg.yaml")));
static DEREK_DAEMON: Lazy<Daemon> =
    Lazy::new(|| daemon_from_yaml(include_str!("test-cfgs/sockets/derek-cfg.yaml")));

static START_DAEMONS: Lazy<()> = Lazy::new(|| {
    Lazy::force(&ALICE_DAEMON);
    Lazy::force(&BOB_DAEMON);
    Lazy::force(&CHARLIE_DAEMON);
    Lazy::force(&DEREK_DAEMON);
});

fn daemon_from_yaml(yaml: &str) -> Daemon {
    let pseudo_json: serde_json::Value = serde_yaml::from_str(yaml)
        .context("syntax error in config file")
        .unwrap();
    let cfg: ConfigFile = serde_json::from_value(pseudo_json).unwrap();
    Daemon::init(cfg).unwrap()
}

// 3 hop, anon

#[test]
fn n2r() {
    let _ = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().compact())
        .with(
            EnvFilter::builder()
                .with_default_directive("earendil=debug".parse().unwrap())
                .from_env_lossy(),
        )
        .try_init();
    env::set_var("SOSISTAB2_NO_SLEEP", "1");
    Lazy::force(&START_DAEMONS);

    // spin up alice, bob, and charlie daemons
    let alice_isk = IdentitySecret::generate();
    let alice_skt = Socket::bind_n2r(&ALICE_DAEMON, alice_isk, None);
    let charlie_isk = CHARLIE_DAEMON.identity();
    let charlie_skt = Socket::bind_n2r(&CHARLIE_DAEMON, charlie_isk, None);

    // alice sends charlie a msg
    smolscale::block_on(async move {
        // sleep to give the nodes time to connect
        Timer::after(Duration::from_secs(5)).await;
        let alice_msg = Bytes::from_static("Hello, dear Charlie!".as_bytes());
        alice_skt
            .send_to(alice_msg.clone(), charlie_skt.local_endpoint())
            .await
            .context("alice sending failed!")
            .unwrap();

        // charlie receives the msg
        let (body, ep) = charlie_skt
            .recv_from()
            .timeout(Duration::from_secs(10))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(body, alice_msg);
        assert_eq!(ep, alice_skt.local_endpoint());
        eprintln!("------------N2R: 1st ASSERT SUCCEEDED!!!------------");
        // charlie responds to alice after waiting 10 secs for the reply blocks
        Timer::after(Duration::from_secs_f32(0.1)).await;
        let charlie_msg = Bytes::from_static("Hello, dear Alice!".as_bytes());
        charlie_skt
            .send_to(charlie_msg.clone(), alice_skt.local_endpoint())
            .await
            .context("charlie sending failed!")
            .unwrap();
        let (body, ep) = alice_skt
            .recv_from()
            .timeout(Duration::from_secs(10))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(body, charlie_msg);
        assert_eq!(ep, charlie_skt.local_endpoint());
        eprintln!("------------N2R: 2nd ASSERT SUCCEEDED!!!------------");
    });
}

#[test]
fn haven() {
    let _ = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().compact())
        .with(
            EnvFilter::builder()
                .with_default_directive("earendil=debug".parse().unwrap())
                .from_env_lossy(),
        )
        .try_init();
    env::set_var("SOSISTAB2_NO_SLEEP", "1");
    Lazy::force(&START_DAEMONS);

    // spin up alice, bob, and charlie daemons
    let alice_isk = IdentitySecret::generate();
    let alice_skt = Socket::bind_haven(&ALICE_DAEMON, alice_isk, None, None);

    let derek_isk = IdentitySecret::generate();
    let derek_skt = Socket::bind_haven(
        &DEREK_DAEMON,
        derek_isk,
        None,
        Some(CHARLIE_DAEMON.identity().public().fingerprint()),
    );

    smolscale::block_on(async move {
        // sleep to give the nodes time to connect
        helpers::sleep(30).await;
        let alice_msg = Bytes::from_static("Hello, anonymous Derek!".as_bytes());
        println!(
            "alice {}'s {} is sending to derek {}'s skt {}",
            ALICE_DAEMON.identity().public().fingerprint(),
            alice_skt.local_endpoint(),
            DEREK_DAEMON.identity().public().fingerprint(),
            derek_skt.local_endpoint()
        );
        alice_skt
            .send_to(alice_msg.clone(), derek_skt.local_endpoint())
            .await
            .context("alice sending failed!")
            .unwrap();
        println!("derek skt: {}", derek_skt.local_endpoint());
        println!(
            "alice d: {}",
            ALICE_DAEMON.identity().public().fingerprint()
        );
        println!(
            "~~~:{}",
            ALICE_DAEMON
                .control_client()
                .graph_dump(true)
                .await
                .unwrap()
        );
        print!(
            "derek d: {}",
            DEREK_DAEMON.identity().public().fingerprint()
        );
        println!(
            "~~~:{}",
            DEREK_DAEMON
                .control_client()
                .graph_dump(true)
                .await
                .unwrap()
        );

        // derek receives the msg
        let (body, ep) = derek_skt
            .recv_from()
            .timeout(Duration::from_secs(10))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(body, alice_msg);
        assert_eq!(ep, alice_skt.local_endpoint());
        eprintln!("------------HAVEN: 1st ASSERT SUCCEEDED!!!------------");
        // derek responds to alice
        let derek_msg = Bytes::from_static("Hello, dear Alice!".as_bytes());
        derek_skt
            .send_to(derek_msg.clone(), alice_skt.local_endpoint())
            .await
            .context("charlie sending failed!")
            .unwrap();
        let (body, ep) = alice_skt
            .recv_from()
            .timeout(Duration::from_secs(10))
            .await
            .context("timed out")
            .unwrap()
            .unwrap();
        assert_eq!(body, derek_msg);
        assert_eq!(ep, derek_skt.local_endpoint());
        eprintln!("------------HAVEN: 2nd ASSERT SUCCEEDED!!!------------");
    })
}

#[test]
fn haven_ascended_pt_ii() {
    helpers::tracing_init();
    helpers::env_vars();

    smolscale::block_on(async {
        let (mut relays, mut clients) = helpers::spawn_network(1, 1, None).unwrap();

        helpers::sleep(30).await;

        // pick an alice and bob
        let alice = clients.pop().unwrap();
        let alice_haven_isk = IdentitySecret::generate();
        let alice_skt = Socket::bind_haven(&alice, alice_haven_isk, None, None);

        let bob = relays.pop().unwrap();
        let bob_haven_isk = IdentitySecret::generate();
        let bob_skt = Socket::bind_haven(
            &bob,
            bob_haven_isk,
            None,
            Some(bob.identity().public().fingerprint()),
        );

        // create and send msg from alice to bob
        let to_bob = b"hello bobert";
        alice_skt
            .send_to(Bytes::copy_from_slice(to_bob), bob_skt.local_endpoint())
            .await
            .unwrap();
        let (from_alice, _) = bob_skt
            .recv_from()
            .timeout(Duration::from_secs(10))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(from_alice.as_ref(), to_bob);

        // create and send msg from bob to alice
        let to_alice = b"hey there, allison";
        bob_skt
            .send_to(Bytes::copy_from_slice(to_alice), alice_skt.local_endpoint())
            .timeout(Duration::from_secs(10))
            .await
            .unwrap()
            .unwrap();
        let (from_bob, _) = alice_skt.recv_from().await.unwrap();

        assert_eq!(from_bob.as_ref(), to_alice);
    });
}
