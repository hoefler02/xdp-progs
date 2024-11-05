#include <stdio.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <stdlib.h>

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 data;
};

const char* pin_dir = "/sys/fs/bpf/xdp_lpm_trie_map";
// const char* pin_dir = "/sys/fs/bpf/xdp/my_map";

void usage(char* prog)
{
        printf("Usage: %s ADD [IP] [PREFIX] [MAGIC]\n", prog);
        printf("or\n");
        printf("Usage: %s SEARCH [IP]\n", prog);
        printf("or\n");
        printf("Usage: %s DUMP\n", prog);
        exit(1);
}

// https://docs.kernel.org/bpf/map_lpm_trie.html
void iterate_lpm_trie(int map_fd)
{
    struct ipv4_lpm_key *cur_key = NULL;
    struct ipv4_lpm_key next_key;
    int magic;
    int err;

    for (;;) {
        err = bpf_map_get_next_key(map_fd, cur_key, &next_key);
        if (err)
            printf("[-] Reached End of Map.\n");
            break;

        bpf_map_lookup_elem(map_fd, &next_key, &magic);
        printf("[+] Found IP %pI4 with Prefix %d and Magic Value %d\n", cur_key->data, cur_key->prefixlen, magic);

        cur_key = &next_key;
    }
}


int main(int argc, char* argv[])
{
    struct bpf_map_info map_expect = { 0 };
    unsigned int ip;
    int prefix;
    int magic;
    int ret;
    char ip_str[INET_ADDRSTRLEN];  // INET_ADDRSTRLEN is defined in arpa/inet.h
    // try to open the lpm bpf map
    int lpm_trie_map_fd = bpf_obj_get(pin_dir);
    if (lpm_trie_map_fd < 0) {
        printf("[-] Failed to open BPF obj.\n");
        return 1;
    }
    if (argc < 2) {
        usage(argv[0]);
    } else if (!strcmp(argv[1], "ADD") && argc == 5) {
        // try to open the lpm bpf map
        if (inet_pton(AF_INET, argv[2], &ip)  != 1) {
            printf("[-] Invalid IP address format: %s\n", argv[2]);
            usage(argv[0]);
        }
        prefix = atoi(argv[3]);
        magic = atoi(argv[4]);
        // build the lpm key structure
        struct ipv4_lpm_key ipv4_key = {
            .prefixlen = prefix,
            .data = ip
        };

        //inet_ntop(AF_INET, &ip, ip_str, INET_ADDRSTRLEN);

        // Print the IP address
        printf("Trying to add IP: %s with Prefix: %d and Magic: %d\n", argv[2], ipv4_key.prefixlen, magic);

        ret = bpf_map_update_elem(lpm_trie_map_fd, &ipv4_key, &magic, BPF_ANY);
        if (!ret) {
            printf("[+] Success!\n");
        } else {
            printf("[-] Failure: Add Returned: %d\n", ret);
        }
    } else if (!strcmp(argv[1], "SEARCH") && argc == 3) {
        inet_pton(AF_INET, argv[2], &ip);
        // build the lpm key structure
        struct ipv4_lpm_key ipv4_key = {
            .data = ip,
            .prefixlen = 32
        };
        ret = bpf_map_lookup_elem(lpm_trie_map_fd, &ipv4_key, &magic);
        printf("[+] Found Magic Value: %d\n", magic);
    } else if (!strcmp(argv[1], "DUMP") && argc == 2) {
        iterate_lpm_trie(lpm_trie_map_fd);
    } else {
        usage(argv[0]);
    }

    return 0;

}
