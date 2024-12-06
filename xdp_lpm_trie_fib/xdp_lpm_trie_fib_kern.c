#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <linux/tcp.h>
#include <stdbool.h>

SEC("xdp")
int xdp_lpm(struct xdp_md *ctx)
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

    __u32 src = ip->saddr;

    bpf_fib_lookup(ctx

}

char _license[] SEC("license") = "GPL";


