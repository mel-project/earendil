use std::{env, time::Duration};

use anyhow::Context;
use bytes::Bytes;
use earendil::{config::ConfigFile, daemon::Daemon, socket::Socket};
use earendil_crypt::IdentitySecret;
use once_cell::sync::Lazy;
use smol::Timer;
use smol_timeout::TimeoutExt;

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
// for maximal visibility, run with
// RUST_LOG=earendil=trace cargo test -- --nocapture

// 3 hop, anon
#[test]
fn n2r() {
    let _ = env_logger::try_init();
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
        Timer::after(Duration::from_secs(20)).await;
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

        // charlie responds to alice
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
    });
}

#[test]
fn haven() {
    let _ = env_logger::try_init();
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
        Timer::after(Duration::from_secs(30)).await;
        let alice_msg = Bytes::from_static("Hello, anonymous Derek!".as_bytes());
        alice_skt
            .send_to(alice_msg.clone(), derek_skt.local_endpoint())
            .await
            .context("alice sending failed!")
            .unwrap();

        // derek receives the msg
        let (body, ep) = derek_skt
            .recv_from()
            .timeout(Duration::from_secs(10))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(body, alice_msg);
        assert_eq!(ep, alice_skt.local_endpoint());

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
            .unwrap()
            .unwrap();
        assert_eq!(body, derek_msg);
        assert_eq!(ep, derek_skt.local_endpoint());
    })
}
