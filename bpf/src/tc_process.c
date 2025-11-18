// tc_drop.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

typedef struct {
    bool gress; //true-egress false-ingress
    uint32_t time_scale;
    uint64_t rate_bps;
} Rule;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, Rule);
    __uint(max_entries, 1);
} cgroup_rules SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

SEC("cgroup_skb/ingress")
int drop_ingress(struct __sk_buff* skb) {
    return 0;
}

SEC("cgroup_skb/egress")
int drop_egress(struct __sk_buff* skb) {
    return 0;
}
