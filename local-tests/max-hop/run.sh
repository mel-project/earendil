#!/bin/bash

gossip_time=170
transfer_size=$((1024*1024*15))

# TCP port we are forwarding from
forward_to=4444

# TCP port we are forwarding to
to_port=8888

SOSISTAB2_NO_SLEEP=1 earendil daemon --config alice.yaml > /dev/null 2>&1 &
SOSISTAB2_NO_SLEEP=1 earendil daemon --config bob.yaml > /dev/null 2>&1 &
SOSISTAB2_NO_SLEEP=1 earendil daemon --config charlie.yaml > /dev/null 2>&1 &
SOSISTAB2_NO_SLEEP=1 earendil daemon --config dan.yaml > /dev/null 2>&1 &
SOSISTAB2_NO_SLEEP=1 earendil daemon --config eve.yaml > /dev/null 2>&1 &
SOSISTAB2_NO_SLEEP=1 earendil daemon --config faythe.yaml > /dev/null 2>&1 &
SOSISTAB2_NO_SLEEP=1 earendil daemon --config grace.yaml > /dev/null 2>&1 &
SOSISTAB2_NO_SLEEP=1 earendil daemon --config heidi.yaml > /dev/null 2>&1 &
SOSISTAB2_NO_SLEEP=1 earendil daemon --config ivan.yaml > /dev/null 2>&1 &
SOSISTAB2_NO_SLEEP=1 earendil daemon --config judy.yaml > /dev/null 2>&1 &

# echo server
rm .fifo
mknod -m 777 .fifo p
cat .fifo | nc -lk 127.0.0.1 $to_port > .fifo &

echo "sleeping for ${gossip_time}s to allow nodes to gossip..."
for i in $(seq 1 $gossip_time); do
    sleep 1
    echo -n "."
done | pv -pt -i1 -s $gossip_time > /dev/null

echo $'\nalice graph:'
earendil control graph-dump
echo "judy graph:"
earendil control --connect 127.0.0.1:10010 graph-dump

echo "starting transfer..."
cat /dev/zero | head -c $transfer_size | nc 127.0.0.1 $forward_to | pv > /dev/null 

killall earendil
killall nc