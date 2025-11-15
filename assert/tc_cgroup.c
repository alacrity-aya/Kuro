#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char license[] SEC("license") = "GPL";

#define CG_ACT_OK 1
#define CG_ACT_SHOT 0

#define NSEC_PER_SEC 1000000000ull

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define ACCEPT 1
#define DROP 0

#define EGRESS 1
#define INGRESS 0

struct rate_bucket {
    __u64 ts_ns;
    __u64 tokens;
};

struct rate_limit {
    __u64* bucket_key;
    __u32 rate_bps;
    __u32 time_scale;
    __u32 packet_len;
    void* buckets;
};

struct flow_rate_info {
    __u64 window_start_ns;
    __u64 last_ns;
    __u64 total_bytes;
    __u64 packet_bytes;
    __u64 rate_bps;
    __u64 instance_rate_bps;
    __u64 peak_rate_bps;
    __u64 smooth_rate_bps;
};

static __inline __u64 start_to_now_ns(void) {
    return bpf_ktime_get_ns();
}

static __always_inline int rate_limit_check(struct rate_limit* rate) {
    __u64 now = bpf_ktime_get_ns();
    __u64 delta_ns;
    struct rate_bucket* b;

    __u64 max_bucket = (rate->rate_bps * rate->time_scale) >> 2;

    b = bpf_map_lookup_elem(rate->buckets, rate->bucket_key);
    if (!b) {
        struct rate_bucket init = { .ts_ns = now, .tokens = max_bucket };
        bpf_map_update_elem(rate->buckets, rate->bucket_key, &init, 0);
        b = bpf_map_lookup_elem(rate->buckets, rate->bucket_key);
        if (!b) {
            return ACCEPT;
        }
    }

    delta_ns = now - b->ts_ns;
    b->tokens += (delta_ns * rate->rate_bps) / NSEC_PER_SEC;
    if (b->tokens > max_bucket) {
        b->tokens = max_bucket;
    }

    b->ts_ns = now;

    if (b->tokens < rate->packet_len) {
        return DROP;
    }

    b->tokens -= rate->packet_len;

    return ACCEPT;
}

static __inline void update_flow_rate(struct flow_rate_info* flow_info, __u32 packet_size) {
    __u64 now = start_to_now_ns();
    flow_info->total_bytes += packet_size;
    flow_info->rate_bps =
        (flow_info->total_bytes * NSEC_PER_SEC) / (now - flow_info->window_start_ns);
    if (now - flow_info->last_ns >= NSEC_PER_SEC) {
        flow_info->instance_rate_bps =
            (flow_info->packet_bytes * NSEC_PER_SEC) / (now - flow_info->last_ns);
        if (flow_info->instance_rate_bps > flow_info->peak_rate_bps) {
            flow_info->peak_rate_bps = flow_info->instance_rate_bps;
        }

        if (flow_info->smooth_rate_bps != 0) {
            flow_info->smooth_rate_bps =
                (flow_info->smooth_rate_bps - (flow_info->smooth_rate_bps >> 3))
                + (flow_info->instance_rate_bps >> 3);
        } else {
            flow_info->smooth_rate_bps = flow_info->instance_rate_bps;
        }
        flow_info->last_ns = now;
        flow_info->packet_bytes = packet_size;
    } else {
        flow_info->packet_bytes += packet_size;
    }
}

struct message_get {
    __u64 instance_rate_bps;
    __u64 rate_bps;
    __u64 peak_rate_bps;
    __u64 smoothed_rate_bps;
    __u64 timestamp;
};

struct cgroup_rule {
    __u64 rate_bps;
    __u8 gress;
    __u32 time_scale;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct flow_rate_info));
    __uint(max_entries, 1);
} flow_rate_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct cgroup_rule);
    __uint(max_entries, 1024);
} cgroup_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct rate_bucket);
    __uint(max_entries, 1024);
} buckets SEC(".maps");

static __inline void send_message(struct message_get* mes) {
    struct message_get* e;

    e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
    if (!e) {
        return;
    }
    *e = *mes;
    e->timestamp = start_to_now_ns();

    bpf_ringbuf_submit(e, 0);
}

static __inline __u32 get_current_pid(void) {
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    if (task) {
        __u32 pid = 0;
        bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid);
        return pid;
    }
    return 0;
}

static __inline __u64 get_cgroup_id(void) {
    return bpf_get_current_cgroup_id();
}

static int cgroup_handle(struct __sk_buff* ctx, int gress) {
    struct cgroup_rule* rule;
    struct message_get mes = { 0 };
    __u32 rule_key = 0;
    __u32 pid = get_current_pid();
    __u64 cgroup_id = get_cgroup_id();

    rule = bpf_map_lookup_elem(&cgroup_rules, &rule_key);
    if (!rule || (rule->gress != gress)) {
        return CG_ACT_OK;
    }

    __u64 now = bpf_ktime_get_ns();
    __u32 flow_key = 1;
    struct flow_rate_info* info = bpf_map_lookup_elem(&flow_rate_stats, &flow_key);
    if (!info) {
        struct flow_rate_info new_flow = { .window_start_ns = now,
                                           .total_bytes = ctx->len,
                                           .packet_bytes = ctx->len,
                                           .last_ns = now,
                                           .instance_rate_bps = 0,
                                           .rate_bps = 0,
                                           .peak_rate_bps = 0,
                                           .smooth_rate_bps = 0 };
        bpf_map_update_elem(&flow_rate_stats, &flow_key, &new_flow, BPF_ANY);
    }
    info = bpf_map_lookup_elem(&flow_rate_stats, &flow_key);
    if (info) {
        update_flow_rate(info, ctx->len);
        mes.rate_bps = info->rate_bps;
        mes.instance_rate_bps = info->rate_bps;
        mes.peak_rate_bps = info->peak_rate_bps;
        mes.smoothed_rate_bps = info->smooth_rate_bps;
    }

    send_message(&mes);

    __u64 bucket_key = cgroup_id;
    struct rate_limit rate = { .bucket_key = &bucket_key,
                               .buckets = &buckets,
                               .packet_len = ctx->len,
                               .rate_bps = rule->rate_bps,
                               .time_scale = rule->time_scale };
    if (rate_limit_check(&rate) == ACCEPT) {
        return CG_ACT_OK;
    }
    return CG_ACT_SHOT;
}

SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff* ctx) {
    return cgroup_handle(ctx, EGRESS);
}

SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff* ctx) {
    return cgroup_handle(ctx, INGRESS);
}
