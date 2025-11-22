// tc_ip.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define NANO_PER_SEC 1000000000ULL
#define ETH_P_IP 0x0800
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define DIR_INGRESS 0
#define DIR_EGRESS 1

char LICENSE[] SEC("license") = "GPL"; // NOLINT(readability-identifier-naming)

// Key:  IP, Port, Protocol, Direction
struct IpKey {
    __u32 ip; // Network Byte Order
    __u16 port; // Network Byte Order
    __u8 proto; // IPPROTO_TCP (6) / UDP (17)
    __u8 gress; // 0: Ingress, 1: Egress
};

// Value: Configuration and runtime statue
struct IpValue {
    // Configuration
    __u64 rate_bps;
    __u64 time_scale; // nanosecond

    // Token Bucket
    __u64 tokens;
    __u64 last_ns;
    struct bpf_spin_lock lock;
};

// Hash Map: IP rule
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct IpKey);
    __type(value, struct IpValue);
    __uint(max_entries, 10240);
} ip_rules SEC(".maps");

typedef struct {
    __u64 accepted_bytes;
    __u64 dropped_bytes;
    __u64 accepted_packets;
    __u64 dropped_packets;
} FLowCounter;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, FLowCounter);
    __uint(max_entries, 1);
} ip_stats SEC(".maps");

static __always_inline int check_limit(struct __sk_buff* skb, __u8 dir) {
    void* data_end = (void*)(long)skb->data_end; // NOLINT(performance-no-int-to-ptr)
    void* data = (void*)(long)skb->data; // NOLINT(performance-no-int-to-ptr)
    struct ethhdr* eth = data;

    if ((void*)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr* ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end)
        return TC_ACT_OK;

    struct IpKey key = { 0 };
    key.proto = ip->protocol;
    key.gress = dir;

    if (dir == DIR_INGRESS) {
        key.ip = ip->saddr; // INGRESS -> limit source ip
    } else {
        key.ip = ip->daddr; // EGRESS -> limit destination ip
    }

    if (ip->protocol == 6) { // TCP
        struct tcphdr* tcp = (void*)(ip + 1);
        if ((void*)(tcp + 1) > data_end)
            return TC_ACT_OK;
        key.port = (dir == DIR_INGRESS) ? tcp->source : tcp->dest;
    } else if (ip->protocol == 17) { // UDP
        struct udphdr* udp = (void*)(ip + 1);
        if ((void*)(udp + 1) > data_end)
            return TC_ACT_OK;
        key.port = (dir == DIR_INGRESS) ? udp->source : udp->dest;
    } else {
        key.port = 0;
    }

    struct IpValue* rule = bpf_map_lookup_elem(&ip_rules, &key);
    if (!rule)
        return TC_ACT_OK;

    int action = TC_ACT_SHOT;
    __u64 now = bpf_ktime_get_ns();
    __u64 pkt_len = skb->len;

    bpf_spin_lock(&rule->lock);

    __u64 delta = now - rule->last_ns;
    if (delta > 0) {
        __u64 capacity_ns = rule->time_scale > 0
            ? rule->time_scale
            : 100000000ULL; // if time_scale == 0 => set time_scale = 100ms
        __u64 capacity_bytes = (rule->rate_bps * capacity_ns) / NANO_PER_SEC;

        if (delta >= capacity_ns) {
            rule->tokens = capacity_bytes;
        } else {
            __u64 new_tokens = (delta * rule->rate_bps) / NANO_PER_SEC;
            rule->tokens += new_tokens;
            if (rule->tokens > capacity_bytes)
                rule->tokens = capacity_bytes;
        }
        rule->last_ns = now;
    }

    if (rule->tokens >= pkt_len) {
        rule->tokens -= pkt_len;
        action = TC_ACT_OK;
    }

    bpf_spin_unlock(&rule->lock);

    __u32 stats_key = 0;
    FLowCounter* st = bpf_map_lookup_elem(&ip_stats, &stats_key);
    if (st) {
        if (action == TC_ACT_SHOT) {
            st->dropped_bytes += pkt_len;
            st->dropped_packets += 1;
        } else {
            st->accepted_bytes += pkt_len;
            st->accepted_packets += 1;
        }
    }

    return action;
}

// TC Classifier Hooks
SEC("classifier/ingress")
int ip_ingress(struct __sk_buff* skb) {
    return check_limit(skb, DIR_INGRESS);
}

SEC("classifier/egress")
int ip_egress(struct __sk_buff* skb) {
    return check_limit(skb, DIR_EGRESS);
}
