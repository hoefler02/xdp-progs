#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <linux/tcp.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_lookup(struct xdp_md *ctx)
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

    // initialize the lookup struct
    struct bpf_fib_lookup params;
    // https://github.com/torvalds/linux/blob/master/samples/bpf/xdp_fwd_kern.c
    if (eth->h_proto == bpf_htons(ETH_P_IP)) { // ipv4
        params.family = AF_INET;
        params.tos = ip->tos;
        params.l4_protocol = ip->protocol;
        params.sport = 0;
        params.dport = 0;
        params.tot_len = ntohs(ip->tot_len);
        params.ipv4_src = ip->saddr;
        params.ipv4_dst = ip->daddr;
    } else {
        return XDP_PASS;
    }
    params.ifindex = ctx->ingress_ifindex;
    // kernel lookup on the params
    int ret = bpf_fib_lookup(ctx, &params, sizeof(params), BPF_FIB_LOOKUP_OUTPUT);

    if (ret ==  BPF_FIB_LKUP_RET_SUCCESS) {
        // good lookup
        return bpf_redirect(params.ifindex, 0);
    } else {
        char msg[] = "Failed to Lookup BPF FIB with Return Code: %d\n";
        bpf_trace_printk(msg, sizeof(msg), ret);
    }

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";


