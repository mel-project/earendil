use earendil::daemon::Daemon;

mod helpers;

#[test]
fn send_chat_msg() {
    helpers::tracing_init();
    helpers::env_vars();

    smolscale::block_on(async {
        let (relays, mut clients) = helpers::spawn_network(3, 9, None).unwrap();

        helpers::sleep(30).await;

        // pick an alice and bob
        let alice = clients.pop().unwrap();
        let alice_fp = alice.identity().public().fingerprint();
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

        // create and send msg from alice to bob
        let to_bob = "hello bobert".to_string();
        alice
            .control_client()
            .send_chat_msg(bob_fp, to_bob.clone())
            .await
            .unwrap();
        let mut bob_chat = bob.control_client().get_chat(alice_fp).await.unwrap();
        let from_alice = bob_chat.pop().unwrap().1;

        assert_eq!(from_alice, to_bob);

        // create and send msg from bob to alice
        let to_alice = "hey there, allison".to_string();
        bob.control_client()
            .send_chat_msg(alice_fp, to_alice.clone())
            .await
            .unwrap();
        let mut alice_chat = alice.control_client().get_chat(bob_fp).await.unwrap();
        let from_bob = alice_chat.pop().unwrap().1;

        assert_eq!(from_bob, to_alice);
    });
}
