use earendil::{
    daemon::Daemon,
    socket::Socket,
    stream::{Stream, StreamListener},
};
use smol::io::{AsyncReadExt, AsyncWriteExt};

mod helpers;

#[test]
fn stream() {
    // helpers::tracing_init();
    helpers::env_vars();

    smolscale::block_on(async {
        let (relays, mut clients) = helpers::spawn_network(3, 3, None).unwrap();

        helpers::sleep(30).await;

        let alice = clients.pop().unwrap();
        let alice_skt = Socket::bind_n2r(&alice, alice.identity(), None);
        let alice_skt_ep = alice_skt.local_endpoint();
        let mut alice_listener = StreamListener::listen(alice_skt);

        let bob_fp = alice
            .control_client()
            .list_neighbors()
            .await
            .unwrap()
            .pop()
            .unwrap();
        let bob = relays
            .into_iter()
            .filter(|daemon| daemon.identity().public().fingerprint() == bob_fp)
            .collect::<Vec<Daemon>>()
            .pop()
            .unwrap();
        let bob_skt = Socket::bind_n2r(&bob, bob.identity(), None);

        let to_bob = b"hello bobert";
        let to_alice = b"hey there, allison";

        smol::spawn(async move {
            let mut alice_stream = alice_listener.accept().await.unwrap();
            println!("alice accepted");

            alice_stream.write_all(to_bob).await.unwrap();
            alice_stream.flush().await.unwrap();
            println!("alice wrote");

            let mut from_bob = [0u8; 100];
            let n = alice_stream.read(&mut from_bob[..]).await.unwrap(); // todo: test stuck here
            println!("alice read");

            assert_eq!(from_bob[..n], to_alice[..]);
            println!("alice asserted");
        })
        .detach();

        let mut bob_stream = Stream::connect(bob_skt, alice_skt_ep).await.unwrap();
        println!("bob connected");

        bob_stream.write_all(to_alice).await.unwrap();
        bob_stream.flush().await.unwrap();
        println!("bob wrote");

        let mut from_alice = [0u8; 100];
        let n = bob_stream.read(&mut from_alice[..]).await.unwrap();
        println!("bob read");

        assert_eq!(from_alice[..n], to_bob[..]);
        println!("bob asserted");
    });
}
