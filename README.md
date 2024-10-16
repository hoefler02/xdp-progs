# XDP Programming

This repository is an assortment of small XDP programs I have written to learn.

## Resources

1. [Firewall with XDP](https://www.kungfudev.com/blog/2023/11/08/beginner-guide-to-xdp-crafting-xdp-based-firewall-with-bcc)
2. [Setting up Namespaces/Virtual Ethernet Devices](https://medium.com/@amazingandyyy/introduction-to-network-namespaces-and-virtual-ethernet-veth-devices-304e0c02d084)
3. [Linux Interfaces for Virtual Networking](https://developers.redhat.com/blog/2018/10/22/introduction-to-linux-interfaces-for-virtual-networking#veth)

## Environment Setup

Using (2), I ran the following commands to create two virtual networking stacks.

```bash
sudo ip netns add net1
sudo ip netns add net2
```

Then we create the pair of virtual ethernet devices.

```bash
sudo ip link add veth1 type veth peer name veth2
```

After that we attach them to the networking namespaces and turn them on.

```bash
sudo ip link set veth1 netns net1
sudo ip netns exec net1 ip link set dev veth1 up

sudo ip link set veth2 netns net2
sudo ip netns exec net2 ip link set dev veth2 up
```

Finally, we add IP addresses.

```bash
sudo ip netns exec net1 ip addr add 192.168.1.1/24 dev veth1 && sudo ip netns exec net1 ip link set dev veth1 up
sudo ip netns exec net2 ip addr add 192.168.1.2/24 dev veth2 && sudo ip netns exec net2 ip link set dev veth2 up
```

## Using the Environment

To use the environment, I use two terminals, running the following commands.

```bash
sudo ip netns exec net1 bash
```
```bash
sudo ip netns exec net2 bash
```

The two sessions have completely isolated networking stacks and can ping/communicate with eachother, making for a great environment to test XDP modules.

In the net2 session I load the XDP modules, and I use net1 to ping/send traffic.

## Compiling the XDP Modules

The following commands are used to compile/inspect an XDP module.

```bash
clang -O2 -g -Wall -target bpf -c TARGET.c -o TARGET.o
llvm-objdump -S TARGET.o
```

Resource (1) is very helpful for writing the modules.

## Running the XDP Modules

The following commands are used on the net2 session to add/remove the XDP modules.

```bash
ip link set dev veth2 xdpgeneric off
ip link set dev veth2 xdpgeneric obj TARGET.o sec xdp
```

Debug output is pushed to `/sys/kernel/debug/tracing/trace_pipe`.
