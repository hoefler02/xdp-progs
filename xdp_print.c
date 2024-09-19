#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_print(struct xdp_md *ctx)
{
    char msg[] = "hello xdp!\n";
    bpf_trace_printk(msg, sizeof(msg));
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
