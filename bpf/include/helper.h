#pragma once

#include "map.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_UNSPEC -1

#define NSEC_PER_SEC 1000000000ULL

#define DEFAULT_EDT_HORIZON_NS (500ULL * 1000000ULL) // 500ms

#define ENABLE_PRINT 0

#if ENABLE_PRINT
    #define kuro_debug(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
    #define kuro_debug(fmt, ...)
#endif

static __always_inline void get_global_config(__u64* horizon) {
    __u32 key = 0;

    struct global_config* cfg = bpf_map_lookup_elem(&config_map, &key);

    if (cfg && cfg->edt_horizon_ns > 0) {
        *horizon = cfg->edt_horizon_ns;
    } else {
        *horizon = DEFAULT_EDT_HORIZON_NS;
    }
}

// Ethernet Header Length
#define ETH_HLEN 14
#define ETH_P_IP 0x0800

/**
 * Parse IPv4 Header
 * @param skb: Socket buffer context
 * @param src_ip: Output parameter, Source IP (Network Byte Order)
 * @param dst_ip: Output parameter, Destination IP (Network Byte Order)
 * @return: 1 on success, 0 on failure (non-IPv4 or out-of-bounds)
 */

static __always_inline int parse_ipv4(struct __sk_buff* skb, __u32* src_ip, __u32* dst_ip) {
    void* data_end = (void*)(long)skb->data_end;
    void* data = (void*)(long)skb->data;

    struct ethhdr* eth = data;
    if ((void*)(eth + 1) > data_end) {
        return 0;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return 0;
    }

    struct iphdr* iph = (void*)(eth + 1);
    if ((void*)(iph + 1) > data_end) {
        return 0;
    }

    if (src_ip)
        *src_ip = iph->saddr;
    if (dst_ip)
        *dst_ip = iph->daddr;

    return 1;
}

// direction: 0 = Download (Host->Pod), 1 = Upload (Pod->Host)
static __always_inline void
update_metrics(__u32 ifindex, __u64 len, int ret, int is_sim, int direction) {
    struct pod_stats* metrics = bpf_map_lookup_elem(&metrics_map, &ifindex);
    if (!metrics) {
        return;
    }

    struct flow_metrics* target;

    if (direction == 0) { // Download
        target = is_sim ? &metrics->sim_download : &metrics->sys_download;
    } else { // Upload
        target = is_sim ? &metrics->sim_upload : &metrics->sys_upload;
    }

    if (ret == TC_ACT_SHOT) {
        target->drop_packets++;
        target->drop_bytes += len;
    } else {
        target->packets++;
        target->bytes += len;
    }
}

static __always_inline u32 log2_u32(u32 v) {
    u32 r;
    u32 shift;

    r = (v > 0xFFFF) << 4;
    v >>= r;
    shift = (v > 0xFF) << 3;
    v >>= shift;
    r |= shift;
    shift = (v > 0xF) << 2;
    v >>= shift;
    r |= shift;
    shift = (v > 0x3) << 1;
    v >>= shift;
    r |= shift;
    r |= (v >> 1);
    return r;
}

static __always_inline u32 log2_u64(u64 v) {
    u32 hi = v >> 32;
    if (hi)
        return log2_u32(hi) + 32 + 1;
    else
        return log2_u32(v) + 1;
}

static __always_inline void update_latency_hist(__u32 ifindex, __u64 latency_ns) {
    struct latency_hist* hist = bpf_map_lookup_elem(&latency_map, &ifindex);
    if (!hist)
        return;

    __u64 slot;

    __u64 latency_us = latency_ns / 1000;

    if (latency_us == 0) {
        slot = 0;
    } else {
        slot = log2_u64(latency_us);
    }

    if (slot >= LATENCY_BUCKETS) {
        slot = LATENCY_BUCKETS - 1;
    }

    hist->buckets[slot]++;
}
