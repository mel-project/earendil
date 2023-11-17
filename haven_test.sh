#!/bin/bash

trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

export SOSISTAB2_NO_SLEEP=1

cargo install --locked --path .
cd cfg_example
# start earendil daemon
earendil daemon --config config.yaml &
sleep 3

# register ourselves as our own rendezvous point!
earendil control bind-haven --skt-id bob --dock 12345 --rendezvous "w0pj999ezrc36spw5zz88nn79z9h7mss"
# bind a haven socket on a different port and message our own haven!
earendil control bind-haven --skt-id alice --dock 23456
sleep 3

earendil control send-msg --skt-id alice --dest "w0pj999ezrc36spw5zz88nn79z9h7mss:12345" --msg "hello bob!"
sleep 3

# receive message as haven
earendil control recv-msg --skt-id bob
# send response message from haven back to client
earendil control send-msg --skt-id bob --dest "w0pj999ezrc36spw5zz88nn79z9h7mss:23456" --msg "hello alice!"
sleep 3

# receive message as client
earendil control recv-msg --skt-id alice
