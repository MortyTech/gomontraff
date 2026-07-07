// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define ETH_P_IP 0x0800
#define TC_ACT_OK 0

struct stats {
    __u64 rx_bytes;
    __u64 tx_bytes;
};

struct lpm_key_v4 {
    __u32 prefixlen;
    __u32 data; 
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct stats);
    __uint(max_entries, 65535);
} traffic_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key_v4);
    __type(value, __u32);
    __uint(max_entries, 256);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} monitored_subnets SEC(".maps");

static __always_inline int process_packet(struct __sk_buff *skb, __u32 is_egress) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    __u32 target_ip = is_egress ? ip->saddr : ip->daddr;

    struct lpm_key_v4 lpm_key = {
        .prefixlen = 32,
        .data = target_ip
    };

    __u32 *is_monitored = bpf_map_lookup_elem(&monitored_subnets, &lpm_key);
    if (is_monitored) {
        struct stats *val = bpf_map_lookup_elem(&traffic_map, &target_ip);
        if (!val) {
            struct stats zero = {0, 0};
            bpf_map_update_elem(&traffic_map, &target_ip, &zero, BPF_NOEXIST);
            val = bpf_map_lookup_elem(&traffic_map, &target_ip);
        }
        if (val) {
            if (is_egress) {
                __sync_fetch_and_add(&val->tx_bytes, skb->len);
            } else {
                __sync_fetch_and_add(&val->rx_bytes, skb->len);
            }
        }
    }
    return TC_ACT_OK;
}

SEC("tc")
int count_ingress(struct __sk_buff *skb) { 
    return process_packet(skb, 0); 
}

SEC("tc")
int count_egress(struct __sk_buff *skb) { 
    return process_packet(skb, 1); 
}
