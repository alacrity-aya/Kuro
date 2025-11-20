// tc_drop.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define ENABLE_PRINT 0

#if ENABLE_PRINT
    #define kuro_debug(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
    #define kuro_debug(fmt, ...)
#endif /* ifdef DEBUG */

#define KURO_TRAFFIC_ACCRPT 1
#define KURO_TRAFFIC_DROP 0
#define EGRESS 1
#define INGRESS 0
#define NANO_PER_SEC 1000000000ULL

char LICENSE[] SEC("license") = "GPL";

typedef struct {
    __u8 gress; //1-egress 0-ingress
    __u64 time_scale; //nanosecond
    __u64 rate_bps;
} rule;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32); // always 0
    __type(value, rule);
    __uint(max_entries, 1);
} cgroup_rules SEC(".maps");

typedef struct {
    __u64 accepted_bytes;
    __u64 dropped_bytes;
    __u64 accepted_packets;
    __u64 dropped_packets;
} FlowCounter;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32); // always 0
    __type(value, FlowCounter);
    __uint(max_entries, 1);
} flow_stats SEC(".maps");

struct BucketState {
    __u64 tokens;
    __u64 last_ns;
    struct bpf_spin_lock lock;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct BucketState);
    __uint(max_entries, 1);
} traffic_bucket SEC(".maps");

// Core rate limiting logic using Token Bucket algorithm
static __u8 rate_limit(__u64 skb_len, rule* r) {
    __u32 key = 0;
    struct BucketState* bucket = bpf_map_lookup_elem(&traffic_bucket, &key);

    if (!bucket) {
        return KURO_TRAFFIC_ACCRPT;
    }

    __u64 now = bpf_ktime_get_ns();
    __u8 decision = KURO_TRAFFIC_DROP;

    bpf_spin_lock(&bucket->lock);

    __u64 delta = now - bucket->last_ns;

    // calculate tokens to replenish
    if (delta > 0) {
        __u64 new_tokens = 0;

        // Default to 0.1s (100ms) burst if time_scale is 0
        __u64 capacity_ns = r->time_scale > 0 ? (__u64)r->time_scale : 100000000ULL;
        __u64 capacity_bytes = (r->rate_bps * capacity_ns) / NANO_PER_SEC;

        // Overflow protection: if delta is larger than the time to fill the bucket,
        // just set tokens to capacity to avoid overflow in multiplication.
        if (delta >= capacity_ns) {
            bucket->tokens = capacity_bytes;
        } else {
            new_tokens = (delta * r->rate_bps) / NANO_PER_SEC;
            bucket->tokens += new_tokens;
            if (bucket->tokens > capacity_bytes) {
                bucket->tokens = capacity_bytes;
            }
        }

        bucket->last_ns = now;
    }

    // consume tokens
    if (bucket->tokens >= skb_len) {
        bucket->tokens -= skb_len;
        decision = KURO_TRAFFIC_ACCRPT;
    } else {
        decision = KURO_TRAFFIC_DROP;
        kuro_debug("Throttled: need %llu, has %llu\n", skb_len, bucket->tokens);
    }

    bpf_spin_unlock(&bucket->lock);

    return decision;
}

static int cgroup_gress_impl(struct __sk_buff* skb, __u8 gress) {
    __u32 key = 0;
    rule* rule = bpf_map_lookup_elem(&cgroup_rules, (void*)&key);
    if (rule == NULL || rule->gress != gress) {
        kuro_debug("rule = %p", rule);
        return KURO_TRAFFIC_ACCRPT;
    }
    if (rule->rate_bps == 0) {
        FlowCounter* st = bpf_map_lookup_elem(&flow_stats, &key);
        if (st) {
            st->accepted_bytes += skb->len;
            st->accepted_packets += 1;
        }
        return KURO_TRAFFIC_ACCRPT;
    }

    __u8 drop = rate_limit(skb->len, rule);

    // Update statistics
    FlowCounter* st = bpf_map_lookup_elem(&flow_stats, &key);
    if (st != NULL) {
        if (drop == KURO_TRAFFIC_DROP) {
            st->dropped_bytes += skb->len;
            st->dropped_packets += 1;
        } else {
            st->accepted_bytes += skb->len;
            st->accepted_packets += 1;
        }
    }
    return drop;
}

SEC("cgroup_skb/ingress")
int limit_ingress_traffic(struct __sk_buff* skb) {
    return cgroup_gress_impl(skb, INGRESS);
}

SEC("cgroup_skb/egress")
int limit_egress_traffic(struct __sk_buff* skb) {
    return cgroup_gress_impl(skb, EGRESS);
}
