// tc_drop.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("cgroup_skb/ingress")
int drop_ingress(struct __sk_buff* skb) {
    return 0;
}

SEC("cgroup_skb/egress")
int drop_egress(struct __sk_buff* skb) {
    return 0;
}
