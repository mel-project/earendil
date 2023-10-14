#!/bin/bash

trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

export SOSISTAB2_NO_SLEEP=1

cargo install --locked --debug --path .

earendil daemon --config cfg_example/config.yaml &
earendil daemon --config cfg_example/config2.yaml