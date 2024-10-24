#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <linux/tcp.h>
#include <stdbool.h>

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 data;
};

// bpf map to store our ips and prefix lens
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 255);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ipv4_lpm_map SEC(".maps");

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

    struct ipv4_lpm_key ipv4_key = {
        .prefixlen = 32,
        .data = src
    };

    // lookup the longest prefix match
    unsigned int* magic = (unsigned int*)bpf_map_lookup_elem(&ipv4_lpm_map, &ipv4_key);

    if (magic) {
        // print the result
        char msg[] = "Received Packet From Source IP: %pI4 and Found Match %d\n";
        bpf_trace_printk(msg, sizeof(msg), &src, *magic);
    } else {
        char msg[] = "Failed to Retrieve Data With Source IP: %pI4\n";
        bpf_trace_printk(msg, sizeof(msg), &src);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";


