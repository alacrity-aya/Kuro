#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct global_config {
    __u64 edt_horizon_ns; // Maximum allowable delay time window
};

// Rate configuration: supports separate settings for upload and download
struct io_rate {
    __u64 rate_upload; // Pod -> Host (bps)
    __u64 rate_download; // Host -> Pod (bps)
};

// EDT State: records the last transmission time
struct edt_state {
    struct bpf_spin_lock lock;
    __u64 t_last;
};

// Map 1: Global configuration
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct global_config);
    __uint(max_entries, 1);
} config_map SEC(".maps");

// Map 2: Rate configuration table (Key: veth_ifindex)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct io_rate);
    __uint(max_entries, 1024);
} rate_map SEC(".maps");

// Map 3: Download direction state table (Host -> Pod)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct edt_state);
    __uint(max_entries, 1024);
} edt_download_state_map SEC(".maps");

// Map 4: Upload direction state table (Pod -> Host)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct edt_state);
    __uint(max_entries, 1024);
} edt_upload_state_map SEC(".maps");

// Map 5: simulation pod white list (Key: IPv4 Address)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // IPv4 Address (Network Byte Order recommended)
    __type(value, __u8); // 1 = Is Simulation Peer
    __uint(max_entries, 65535);
} simulation_peers_map SEC(".maps");

// =============================================================
// XDP Ingress Protection Structures
// =============================================================

// Ingress Rate Config (Sys Traffic Limit)
struct ingress_config {
    __u64 limit_bps; // Bandwidth limit in bits per second
    __u64 burst_bytes; // Max burst size in bytes
};

// Ingress Token Bucket State
struct ingress_state {
    struct bpf_spin_lock lock;
    __u64 last_updated; // Nanoseconds
    __u64 tokens; // Current tokens (bytes)
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
