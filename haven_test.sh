#!/bin/bash

trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

export SOSISTAB2_NO_SLEEP=1

cargo install --locked --path .
cd cfg_example
# start earendil daemon
earendil daemon --config config.yaml &
sleep 3

# register ourselves as our own rendezvous point!
earendil control bind-haven --socket-id bob --dock 12345 --rendezvous "w0pj999ezrc36spw5zz88nn79z9h7mss"
# bind a haven socket on a different port and message our own haven!
earendil control bind-haven --socket-id alice --dock 23456
sleep 3

earendil control send-message --socket-id alice --destination "w0pj999ezrc36spw5zz88nn79z9h7mss::12345" --message "hello bob!"
sleep 3

# receive message as haven
earendil control recv-message --socket-id bob
# send response message from haven back to client
earendil control send-message --socket-id bob --destination "w0pj999ezrc36spw5zz88nn79z9h7mss::23456" --message "hello alice!"
sleep 3

# receive message as client
earendil control recv-message --socket-id alice