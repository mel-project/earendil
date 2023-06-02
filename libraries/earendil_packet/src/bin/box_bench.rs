use std::time::Instant;

use earendil_packet::crypt::{box_decrypt, box_encrypt, OnionSecret};

fn main() {
    let message = vec![0; 16384];

    let recipient_sk = OnionSecret::generate();
    let recipient_pk = recipient_sk.public();

    let iterations = 100_000;

    let start_time_encrypt = Instant::now();

    for _ in 0..iterations {
        let _encrypted_message = box_encrypt(&message[..], &recipient_pk);
    }

    let duration_encrypt = start_time_encrypt.elapsed();

    let (encrypted_message, _) = box_encrypt(&message[..], &recipient_pk);
    let start_time_decrypt = Instant::now();

    for _ in 0..iterations {
        let _decrypted_message = box_decrypt(&encrypted_message[..], &recipient_sk).unwrap();
    }

    let duration_decrypt = start_time_decrypt.elapsed();

    let encryption_speed = (iterations as f64) / duration_encrypt.as_secs_f64();
    let decryption_speed = (iterations as f64) / duration_decrypt.as_secs_f64();

    println!(
        "Encryption speed: {:.2} operations/second",
        encryption_speed
    );
    println!(
        "Decryption speed: {:.2} operations/second",
        decryption_speed
    );
}
