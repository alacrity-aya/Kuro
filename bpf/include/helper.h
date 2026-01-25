#pragma once

#include "map.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_UNSPEC -1

#define NSEC_PER_SEC 1000000000ULL
#define DEFAULT_EDT_HORIZON_NS (2ULL * NSEC_PER_SEC)

#define ENABLE_PRINT 1

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
