use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use earendil_crypt::{Fingerprint, IdentitySecret};
use earendil_packet::{
    crypt::OnionSecret, ForwardInstruction, InnerPacket, Message, RawPacket, ReplyBlock,
};

fn generate_forward_instructions(n: usize) -> Vec<(ForwardInstruction, OnionSecret)> {
    (0..n)
        .map(|_| {
            let our_sk = OnionSecret::generate();
            let this_pubkey = our_sk.public();

            let next_fingerprint = Fingerprint::from_bytes(&[10; 20]);
            (
                ForwardInstruction {
                    this_pubkey,
                    next_fingerprint,
                },
                our_sk,
            )
        })
        .collect()
}

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("generate an OnionSecret", |b| {
        b.iter(|| {
            black_box(OnionSecret::generate());
        })
    });

    // RawPacket and ReplyBlock benchmarking
    for route_length in [1, 4, 8] {
        let route = generate_forward_instructions(route_length)
            .into_iter()
            .map(|s| s.0)
            .collect::<Vec<_>>();
        let destination_sk = OnionSecret::generate();
        let destination = destination_sk.public();
        let payload = InnerPacket::Message(Message {
            source_dock: 0u32,
            dest_dock: 0u32,
            body: vec![Bytes::from_static(b"hello world")],
        });
        let my_isk = IdentitySecret::generate();
        let my_osk = OnionSecret::generate();
        let my_opk = my_osk.public();

        c.bench_function(&format!("{route_length}-hop RawPacket construction"), |b| {
            b.iter(|| {
                black_box(RawPacket::new_normal(
                    &route,
                    &destination,
                    payload.clone(),
                    &my_isk,
                ))
            });
        });

        let my_anon_osk = OnionSecret::generate();
        let my_anon_isk = IdentitySecret::generate();
        c.bench_function(
            &format!("{route_length}-hop ReplyBlock construction"),
            |b| {
                b.iter(|| {
                    black_box(ReplyBlock::new(
                        &route,
                        &my_opk,
                        my_anon_osk.clone(),
                        my_anon_isk,
                    ))
                });
            },
        );
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
