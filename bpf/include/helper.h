#pragma once

#include "map.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h>

// 简单的包头偏移常量
#define ETH_HLEN 14

static __always_inline int parse_flow_key(struct __sk_buff* skb, struct flow_key* key) {
    void* data_end = (void*)(long)skb->data_end;
    void* data = (void*)(long)skb->data;
    struct ethhdr* eth = data;
    struct iphdr* iph;
    struct tcphdr* tcph;
    struct udphdr* udph;

    // 1. 检查以太网头
    if (data + ETH_HLEN > data_end)
        return -1;

    // 只处理 IPv4 (0x0800)
    if (eth->h_proto != bpf_htons(0x0800))
        return -1;

    // 2. 检查 IP 头
    iph = data + ETH_HLEN;
    if ((void*)(iph + 1) > data_end)
        return -1;

    key->src_ip = iph->saddr;
    key->dst_ip = iph->daddr;
    key->proto = iph->protocol;

    // 计算 L4 头部偏移
    int ip_hlen = iph->ihl * 4;
    void* l4_header = (void*)iph + ip_hlen;

    // 3. 解析 TCP/UDP 端口
    if (iph->protocol == 6) { // TCP
        tcph = l4_header;
        if ((void*)(tcph + 1) > data_end)
            return -1;
        key->src_port = tcph->source;
        key->dst_port = tcph->dest;
    } else if (iph->protocol == 17) { // UDP
        udph = l4_header;
        if ((void*)(udph + 1) > data_end)
            return -1;
        key->src_port = udph->source;
        key->dst_port = udph->dest;
    } else {
        key->src_port = 0;
        key->dst_port = 0;
    }

    return 0;
}
