#!/bin/sh

mkdir -p ./coverage
CARGO_INCREMENTAL=0 RUSTFLAGS='-Cinstrument-coverage' LLVM_PROFILE_FILE='./coverage/cargo-test-%p-%m.profraw' cargo test
grcov coverage --binary-path ./target/debug/deps/ -s . -t html --branch --ignore-not-existing -o coverage/html/
xdg-open coverage/html/index.html
