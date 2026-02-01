#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// =============================================================
// 1. Data Structures
// =============================================================

struct global_config {
    __u64 edt_horizon_ns;
};

// Default Rate Configuration (Bandwidth Limits)
struct io_rate {
    __u64 cost_per_byte_sim_upload; // e.g. 10Mbps
    __u64 cost_per_byte_sim_download;
    __u64 cost_per_byte_sys_upload; // e.g. 990Mbps
    __u64 cost_per_byte_sys_download;
};

// TODO: can be improved
// Physics Model (Per-Link Policy)
struct link_policy {
    __u64 bandwidth_limit; // bps (0 = Use Default Sim Rate)
    __u64 queue_depth_ns; // Horizon (0 = Use Global)
    __u64 base_latency_ns; // Propagation Delay
    __u64 jitter_ns; // Jitter Amplitude
    __u32 corruption_rate_ppm; // Packet Loss (Parts Per Million)
    __u32 _padding; // Align to 8 bytes
};

struct edt_state {
    struct bpf_spin_lock lock;
    __u64 t_last;
};

#define MAX_IFINDEX_CAP 4096
#define MAX_STATE_ENTRIES (MAX_IFINDEX_CAP * 2)

// Map 1: Global configuration
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct global_config);
    __uint(max_entries, 1);
} config_map SEC(".maps");

// Map 2: Rate configuration table (Key: veth_ifindex)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct io_rate);
    __uint(max_entries, MAX_IFINDEX_CAP);
} rate_map SEC(".maps");

// Map 3: Download direction state table (Host -> Pod)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct edt_state);
    __uint(max_entries, MAX_STATE_ENTRIES);
} edt_download_state_map SEC(".maps");

// Map 4: Upload direction state table (Pod -> Host)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct edt_state);
    __uint(max_entries, MAX_STATE_ENTRIES);
} edt_upload_state_map SEC(".maps");

struct policy_key {
    __u32 src_ip;
    __u32 dst_ip;
};

// Map 5: Topology Policy Map
// Key: Policy Key (Network Byte Order)
// Value: Physics Model
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct policy_key);
    __type(value, struct link_policy);
    __uint(max_entries, 65535);
} topology_policy_map SEC(".maps");

// =============================================================
// XDP Ingress Protection Structures
// =============================================================

// Ingress Rate Config (Sys Traffic Limit)
struct ingress_config {
    __u64 cost_per_byte_ns_scaled;
    __u64 burst_ns; // burst_bytes converted to time: (burst_bytes * 8 * 10^9) / limit_bps
};

// Ingress Token Bucket State
struct ingress_state {
    struct bpf_spin_lock lock;
    __u64 last_updated; // Nanoseconds
    __u64 tokens_ns; // Accumulated sendable time
};

// Map 6: Ingress Configuration (Key: 0)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct ingress_config);
    __uint(max_entries, 1);
} ingress_config_map SEC(".maps");

// Map 7: Ingress Runtime State (Key: 0)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct ingress_state);
    __uint(max_entries, 1);
} ingress_state_map SEC(".maps");

// =============================================================
// Flow Metrics Structures
// =============================================================

struct flow_metrics {
    __u64 packets;
    __u64 bytes;
    __u64 drop_packets;
    __u64 drop_bytes;
};

struct pod_stats {
    struct flow_metrics sim_download;
    struct flow_metrics sim_upload;
    struct flow_metrics sys_download;
    struct flow_metrics sys_upload;
};

// Map 8: flow metrics (Key: ifindex, Value: pod_stats)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u32);
    __type(value, struct pod_stats);
    __uint(max_entries, 1024);
} metrics_map SEC(".maps");

#define LATENCY_BUCKETS 16
struct latency_hist {
    __u64 buckets[LATENCY_BUCKETS];
};

// Map 9: delay histogram (Key: ifindex)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u32);
    __type(value, struct latency_hist);
    __uint(max_entries, 1024);
} latency_map SEC(".maps");
