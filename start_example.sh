#!/bin/bash

trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

export SOSISTAB2_NO_SLEEP=1

cargo install --locked --debug --path .
cd cfg_example
earendil daemon --config config.yaml &
sleep 1
earendil daemon --config config2.yaml