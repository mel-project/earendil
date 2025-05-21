use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use earendil_crypt::{AnonEndpoint, RelayFingerprint, RemoteId};
use earendil_topology::NodeAddr;
use earendil_packet::{
    crypt::DhSecret, ForwardInstruction, InnerPacket, Message, PrivacyConfig, RawPacket, Surb,
};

fn generate_forward_instructions(n: usize) -> Vec<(ForwardInstruction, DhSecret)> {
    (0..n)
        .map(|_| {
            let our_sk = DhSecret::generate();
            let this_pubkey = our_sk.public();

            let next_hop = NodeAddr::new(RelayFingerprint::from_bytes(&[10; 32]), 0);
            (
                ForwardInstruction {
                    this_pubkey,
                    next_hop,
                },
                our_sk,
            )
        })
        .collect()
}

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("generate an OnionSecret", |b| {
        b.iter(|| {
            black_box(DhSecret::generate());
        })
    });

    // RawPacket and ReplyBlock benchmarking
    for route_length in [1, 4, 8] {
        let route = generate_forward_instructions(route_length)
            .into_iter()
            .map(|s| s.0)
            .collect::<Vec<_>>();
        let destination_sk = DhSecret::generate();
        let destination = destination_sk.public();
        let payload = InnerPacket::Message(Message {
            relay_dock: 0u32,
            body: Bytes::from_static(b"hello world"),
            remaining_surbs: 0,
        });
        let my_anon_id = AnonEndpoint::random();
        let my_osk = DhSecret::generate();
        let my_opk = my_osk.public();

        c.bench_function(&format!("{route_length}-hop RawPacket construction"), |b| {
            b.iter(|| {
                black_box(RawPacket::new_normal(
                    &route,
                    &destination,
                    payload.clone(),
                    RemoteId::Anon(my_anon_id),
                    PrivacyConfig::default(),
                ))
            });
        });

        let first_peeler = NodeAddr::new(RelayFingerprint::from_bytes(&[10; 32]), 0);

        c.bench_function(
            &format!("{route_length}-hop ReplyBlock construction"),
            |b| {
                b.iter(|| {
                    black_box(Surb::new(
                        &route,
                        first_peeler,
                        &my_opk,
                        0,
                        my_anon_id,
                        PrivacyConfig::default(),
                    ))
                });
            },
        );
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
