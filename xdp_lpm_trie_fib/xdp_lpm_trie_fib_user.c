#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 data;
};

const char* pin_dir = "/sys/fs/bpf/xdp_lpm_trie_map";
// const char* pin_dir = "/sys/fs/bpf/xdp/my_map";

void usage(char* prog)
{
        printf("Usage: %s [file.txt]\n", prog);
        printf("OR\n");
        printf("%s CLEAR\n", prog);
        exit(1);
}

void clear_lpm_trie(int map_fd)
{
        struct ipv4_lpm_key *cur_key = NULL;
        struct ipv4_lpm_key next_key;
        char ip_str[INET_ADDRSTRLEN];  // INET_ADDRSTRLEN is defined in arpa/inet.h
        int value;
        int err;

        for (;;) {
                err = bpf_map_get_next_key(map_fd, cur_key, &next_key);
                if (err)
                        break;

                bpf_map_lookup_elem(map_fd, &next_key, &value);

                /* Use key and value here */
                inet_ntop(AF_INET, &next_key.data, ip_str, INET_ADDRSTRLEN);
                printf("Deleting IP %s with Prefix %d and Value %d!\n", ip_str, next_key.prefixlen, value);
                bpf_map_delete_elem(map_fd, &next_key);

                cur_key = &next_key;
        }
}

int main(int argc, char* argv[])
{
    unsigned int ip;
    int prefix;
    int magic = 0;
    int ret;
    char* ip_str;
    FILE *table;
    char *line = NULL;
    ssize_t len = 0;
    char *maskstr = NULL;
    int idx, read, mask;
    // try to open the lpm bpf map
    int lpm_trie_map_fd = bpf_obj_get(pin_dir);
    if (lpm_trie_map_fd < 0) {
        printf("[-] Failed to open BPF obj.\n");
        return 1;
    }


        // build the lpm key structure
        struct ipv4_lpm_key ipv4_key = {
            .prefixlen = mask,
            .data = ip
        };

        // Print the IP address
        printf("Trying to add IP: %s with Prefix: %d and Magic: %d\n", ip_str, ipv4_key.prefixlen, magic);

        ret = bpf_map_update_elem(lpm_trie_map_fd, &ipv4_key, &magic, BPF_ANY);
        if (!ret) {
            printf("[+] Success!\n");
        } else {
            printf("[-] Failure: Add Returned: %d\n", ret);
        }
        magic++;


    return 0;

}
