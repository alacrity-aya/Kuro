#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// 定义五元组 Key
struct flow_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 proto;
} __attribute__((packed));

// 定义流的状态 Value
struct flow_state {
    __u64 tstamp; // 该流上一个包预计发送完毕的时间 (EDT)
    struct bpf_spin_lock lock; // 锁，防止并发更新导致时间计算错误
};

// 定义 Map: 使用 LRU Hash，避免流太多导致内存溢出
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096); // 支持 4096 个并发流
    __type(key, struct flow_key);
    __type(value, struct flow_state);
} flow_map SEC(".maps");

// 设定全局限速带宽 (例如: 100Mbps)
// 100 Mbps = 12.5 MB/s = 12,500,000 bytes/sec
// ns per byte = 1,000,000,000 / 12,500,000 = 80 ns/byte
#define RATE_NS_PER_BYTE 80
