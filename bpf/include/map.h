#pragma once

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define NSEC_PER_SEC 1000000000ULL
#define NSEC_PER_MSEC 1000000ULL

#define ENABLE_PRINT 0

#if ENABLE_PRINT
    #define kuro_debug(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
    #define kuro_debug(fmt, ...)
#endif /* ENABLE_PRINT */

struct rule_key {
    __u32 ifindex;
    __u32 ipv4; // Destination IP for Ingress, Source IP for Egress
};

// token bucket
struct bucket_state {
    __u64 tokens;
    __u64 last_ns;
    struct bpf_spin_lock lock;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct rule_key);
    __type(value, struct bucket_state);
} bucket_state_map SEC(".maps");

struct filter_spec {
    __u32 dest_ip; // Network Byte Order (0 = any)
    __u16 dest_port; // Network Byte Order (0 = any)
    __u8 proto; // IPPROTO_TCP/UDP/ICMP (0 = any)
    __u8 pad;
};

// traffic rule
struct netem_rule {
    struct filter_spec filter;
    __u32 loss_threshold;
    __u64 jitter_ms;
    __u64 delay_ms;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct rule_key);
    __type(value, struct netem_rule);
} netem_rule_map SEC(".maps");

// traffic rule
struct traffic_rule {
    struct filter_spec filter;
    __u64 rate_bytes;
    __u64 burst_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct rule_key);
    __type(value, struct traffic_rule);
} traffic_rule_map SEC(".maps");

// count flow
// TODO: should count every link
struct flow_counter {
    // Ingress (Rx from Host perspective, Container Upload)
    __u64 rx_bytes;
    __u64 rx_packets;
    __u64 rx_dropped_bytes;
    __u64 rx_dropped_packets;

    // Egress (Tx from Host perspective, Container Download)
    __u64 tx_bytes;
    __u64 tx_packets;
    __u64 tx_dropped_bytes;
    __u64 tx_dropped_packets;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct rule_key); // iface_index
    __type(value, struct flow_counter);
    __uint(max_entries, 1024);
} flow_counter_map SEC(".maps");
