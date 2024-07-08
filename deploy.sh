#!/bin/sh

cargo build  --release --locked --target x86_64-unknown-linux-musl

# rsync binary to bootstrap node & restart
rsync -az --info=progress2 ./target/x86_64-unknown-linux-musl/release/earendil root@62.210.93.59:/usr/local/bin/
ssh root@62.210.93.59 'systemctl restart earendil-free && systemctl restart earendil-paid'
