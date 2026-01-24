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
