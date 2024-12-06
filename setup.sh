#!/bin/bash

# set up the development environment

sudo ip netns add net1
sudo ip netns add net2

sudo ip link add veth1 type veth peer name veth2

sudo ip link set veth1 netns net1
sudo ip netns exec net1 ip link set dev veth1 up

sudo ip link set veth2 netns net2
sudo ip netns exec net2 ip link set dev veth2 up

sudo ip netns exec net1 ip addr add 192.168.1.1/24 dev veth1 && sudo ip netns exec net1 ip link set dev veth1 up
sudo ip netns exec net2 ip addr add 192.168.1.2/24 dev veth2 && sudo ip netns exec net2 ip link set dev veth2 up

sudo tmux new-session -d -s xdp-session

sudo tmux send-keys "ip netns exec net1 bash" C-m
sudo tmux send-keys "ifconfig" C-m

sudo tmux split-window -h

sudo tmux send-keys "ip netns exec net2 bash" C-m
sudo tmux send-keys "ifconfig" C-m

sudo tmux attach -t xdp-session

