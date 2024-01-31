use earendil::{
    daemon::Daemon,
    socket::Socket,
    stream::{Stream, StreamListener},
};
use helpers::gen_seed;
use smol::io::{AsyncReadExt, AsyncWriteExt};
use tracing_test::traced_test;

mod helpers;

#[test]
#[traced_test]
fn stream() {
    // helpers::tracing_init();
    helpers::env_vars();

    let seed = gen_seed("stream");
    let (mut relays, mut clients) = helpers::spawn_network(2, 2, Some(seed)).unwrap();
    // let (relay_configs, client_configs) = generate_network(2, 2, None).unwrap();
    // for i in 0..2 {
    //     helpers::config_to_yaml_file(&relay_configs[i], &format!("./zzz/relay{i}")).unwrap();
    //     helpers::config_to_yaml_file(&client_configs[i], &format!("./zzz/client{i}")).unwrap();
    // }
    // let relays = configs_to_daemons(relay_configs.clone()).unwrap();
    // let mut clients = configs_to_daemons(client_configs).unwrap();

    smolscale::block_on(async move {
        helpers::sleep(5).await;

        let alice = clients.pop().unwrap();
        let alice_skt = Socket::bind_n2r(&alice, alice.identity(), None);
        let alice_skt_ep = alice_skt.local_endpoint();
        let mut alice_listener = StreamListener::listen(alice_skt);

        let bob = relays.pop().unwrap(); // todo: test only works w/ neighbors?
        let bob_skt = Socket::bind_n2r(&bob, bob.identity(), None);

        let to_bob = b"hello bobert";
        let to_alice = b"hey there, allison";

        // let (sender, receiver) = smol::channel::bounded(1);

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

            // sender.send(()).await.unwrap();
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

        // receiver.recv().await.unwrap()
    });
}
