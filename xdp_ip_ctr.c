#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <linux/tcp.h>
#include <stdbool.h>

// bpf map to store our ips and counters
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 16);
} ip_ctr SEC(".maps");

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
    // message format
    char msg[] = "%pI4:%d\n";

    // look up the ip address
    unsigned int* ctr = bpf_map_lookup_elem(&ip_ctr, &src);
    if (ctr) {
        // add to the counter if it exists
        __sync_fetch_and_add(ctr, 1);
        bpf_trace_printk(msg, sizeof(msg), &src, *ctr);
    } else {
        // add a new entry for the ip address
        unsigned int init = 1;
        bpf_map_update_elem(&ip_ctr, &src, &init, BPF_NOEXIST);
        bpf_trace_printk(msg, sizeof(msg), &src, 1);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
