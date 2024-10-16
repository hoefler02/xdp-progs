#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <linux/tcp.h>

SEC("xdp")
int xdp_ip_grab(struct xdp_md *ctx)
{
    // get the data from the xdp_md struct
    void *data_end = (void*)(long)ctx->data_end;
    void *data = (void*)(long)ctx->data;

    // the data should represent an ethhdr struct
    struct ethhdr *eth = data;

    // ensure the packet includes a full eth header
    if (data + sizeof(struct ethhdr) > data_end)
    {
        return XDP_PASS;
    }

    // make sure it is an ip packet
    if (eth->h_proto != __constant_htons(ETH_P_IP))
    {
        return XDP_PASS;
    }

    // get the ip header right after the ethernet header
    struct iphdr *ip = data + sizeof(struct ethhdr);

    // ensure the packet includes the full ip header
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
    {
        return XDP_PASS;
    }

    unsigned int src = ip->saddr;
    unsigned int dst = ip->daddr;

    // print the ip address
    char msg[] = "Received Packet From Source IP: %pI4 and Destination IP: %pI4\n";
    bpf_trace_printk(msg, sizeof(msg), &src, &dst);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
