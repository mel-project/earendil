#!/bin/bash

trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

export SOSISTAB2_NO_SLEEP=1

cargo run -- daemon --config cfg_example/config.yaml &
cargo run -- daemon --config cfg_example/config2.yaml