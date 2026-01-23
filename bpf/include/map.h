#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct global_config {
    __u64 edt_horizon_ns; // Config: EDT_HORIZON_NS
    __u64 tbf_burst_bytes; // Config: TBF_BURST_BYTES
};

struct tbf_state {
    struct bpf_spin_lock lock;
    __u64 last_tstamp;
    __u64 tokens;
};

struct edt_state {
    struct bpf_spin_lock lock;
    __u64 t_last;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct global_config);
    __uint(max_entries, 1);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
} rate_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct edt_state);
    __uint(max_entries, 1024);
} edt_state_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct tbf_state);
    __uint(max_entries, 1024);
} tbf_state_map SEC(".maps");
