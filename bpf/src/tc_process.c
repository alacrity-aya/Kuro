// tc_drop.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define ENABLE_PRINT 1
#ifdef ENABLE_PRINT
    #define kuro_debug(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
    #define debug(fmt, ...)
#endif /* ifdef DEBUG */

#define KURO_TRAFFIC_ACCRPT 1
#define KURO_TRAFFIC_DROP 0
#define EGRESS 1
#define INGRESS 0

char LICENSE[] SEC("license") = "GPL";

typedef struct {
    __u8 gress; //1-egress 0-ingress
    __u32 time_scale;
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
} flow_counter;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32); // always 0
    __type(value, flow_counter);
    __uint(max_entries, 1);
} flow_stats SEC(".maps");

static __u8 rate_limit() {
    return KURO_TRAFFIC_ACCRPT;
}

static int cgroup_gress_impl(struct __sk_buff* skb, __u8 gress) {
    __u32 key = 0;
    rule* rule = bpf_map_lookup_elem(&cgroup_rules, (void*)&key);
    if (rule == NULL || rule->gress != gress) {
        kuro_debug("rule = %p", rule);
        return KURO_TRAFFIC_ACCRPT;
    }
    bpf_printk(
        "Rule = {.gress = %u, .time_scale = %u, .rate_bps = %llu}, gress = %u\n",
        rule->gress,
        rule->time_scale,
        rule->rate_bps,
        gress
    );

    flow_counter* st = bpf_map_lookup_elem(&flow_stats, &key);

    if (st == NULL) {
        return KURO_TRAFFIC_DROP;
    }
    __u8 drop = rate_limit();

    if (drop == KURO_TRAFFIC_DROP) {
        kuro_debug("drop = %d\n", drop);
        st->dropped_bytes += skb->len;
        st->dropped_packets += 1;
    } else {
        kuro_debug("drop = %d\n", drop);
        st->accepted_bytes += skb->len;
        st->accepted_packets += 1;
    }
    return drop;
}

SEC("cgroup_skb/ingress")
int drop_ingress(struct __sk_buff* skb) {
    kuro_debug("%s is called\n", __func__);
    return cgroup_gress_impl(skb, INGRESS);
}

SEC("cgroup_skb/egress")
int drop_egress(struct __sk_buff* skb) {
    kuro_debug("%s is called\n", __func__);
    return cgroup_gress_impl(skb, EGRESS);
}
