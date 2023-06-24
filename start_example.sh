#!/bin/bash

cargo run -- daemon --config cfg_example/config.yaml &
cargo run -- daemon --config cfg_example/config2.yaml