#!/bin/sh

cargo build  --release --locked --target x86_64-unknown-linux-musl
mv ./target/x86_64-unknown-linux-musl/release/earendil ./target/x86_64-unknown-linux-musl/release/earendil-testing

# rsync binary to example-relay-free & restart
rsync -az --info=progress2 ./target/x86_64-unknown-linux-musl/release/earendil-testing root@62.210.93.59:/usr/local/bin/
ssh root@62.210.93.59 'systemctl restart earendil-testing'