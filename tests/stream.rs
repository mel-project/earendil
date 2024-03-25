use std::time::Duration;

use earendil::{HavenEndpoint, HavenListener, PooledListener, PooledVisitor};
use earendil_crypt::HavenIdentitySecret;

use smol::{
    future::FutureExt as _,
};


mod helpers;

#[test]
fn stream() {
    helpers::init_logs();

    let seed = helpers::gen_seed("haven");
    let (mut relays, mut clients) = helpers::spawn_network(2, 4, Some(seed)).unwrap();

    smolscale::block_on(async move {
        helpers::sleep(15).await;

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
        let bob_listener = PooledListener::new(
            HavenListener::bind(&bob.ctx(), bob_haven_id, bob_haven_port, rendezvous)
                .await
                .unwrap(),
        );
        eprintln!("pool bawb obtained");

        let bob_process = async {
            for _ in 0..10 {
                let _bob_conn = bob_listener.accept().await.unwrap();
                eprintln!("got a conn at bawb");
            }
        };
        let alice_process = async {
            smol::Timer::after(Duration::from_secs(5)).await;
            let alice = clients.pop().unwrap();
            let alice_pool = PooledVisitor::new(alice.ctx());
            for _ in 0..10 {
                alice_pool
                    .connect(
                        HavenEndpoint::new(bob_haven_id.public().fingerprint(), bob_haven_port),
                        b"",
                    )
                    .await
                    .unwrap();
            }
            smol::future::pending().await
        };

        bob_process.race(alice_process).await
    });
}
