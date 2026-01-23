#include "include/helper.h"
#include "include/map.h"

// Container NS      |         Host NS
// -------------------------+-------------------------
//                          |
//       [ Pod eth0 ]       |    [ Host veth (lxc) ]
//            |             |            |
//            |             |            |
// (Pod Egress) ⬇️          |            ⬇️ (Host Ingress)
//            |             |            |
//            +-------------+----------> * HandleEdtEgress (AttachTCXIngress)
//                          |            |
//                          |            v
//                          |      (Linux Kernel Stack)
//                          |            |
//                          |            v
//            +-------------+----------< * HandleTbfIngress (AttachTCXEgress)
// (Pod Ingress) ⬆️          |            |
//            |             |            ⬆️ (Host Egress)
//            |             |            |
//       [ Pod eth0 ]       |    [ Host veth (lxc) ]

// Helper function: Fetch configuration; return default values if not configured
static __always_inline void get_global_config(__u64* horizon, __u64* burst) {
    __u32 key = 0;
    struct global_config* cfg = bpf_map_lookup_elem(&config_map, &key);

    if (cfg) {
        *horizon = cfg->edt_horizon_ns;
        *burst = cfg->tbf_burst_bytes;

        // Defensive programming: Prevent division-by-zero or logic deadlocks
        // if userspace provides a 0 value.
        if (*horizon == 0)
            *horizon = DEFAULT_EDT_HORIZON_NS;
        if (*burst == 0)
            *burst = DEFAULT_TBF_BURST_BYTES;
    } else {
        *horizon = DEFAULT_EDT_HORIZON_NS;
        *burst = DEFAULT_TBF_BURST_BYTES;
    }
}

// ==========================================
// Scenario A: Container Egress (Pod -> World)
// ==========================================
SEC("tc/edt_egress")
int handle_edt_egress(struct __sk_buff* skb) {
    __u32 ifindex = skb->ingress_ifindex;

    // ... (rate_map lookup logic same as before) ...
    __u64* rate_bps = bpf_map_lookup_elem(&rate_map, &ifindex);
    if (!rate_bps || *rate_bps == 0)
        return TC_ACT_OK;

    struct edt_state* st = bpf_map_lookup_elem(&edt_state_map, &ifindex);
    if (!st)
        return TC_ACT_OK;

    // --- New: Read dynamic configuration ---
    __u64 horizon_ns, burst_bytes; // burst is unused here but read for function consistency
    get_global_config(&horizon_ns, &burst_bytes);

    __u64 rate = *rate_bps;
    __u64 now = bpf_ktime_get_ns();
    __u64 packet_len = skb->len;
    __u64 packet_time_ns = (packet_len * NSEC_PER_SEC) / rate;
    __u64 t_send;

    bpf_spin_lock(&st->lock);

    __u64 t_start = st->t_last;
    if (t_start < now)
        t_start = now;

    t_send = t_start + packet_time_ns;

    // --- Modified: Use variable horizon_ns ---
    if (t_send > now + horizon_ns) {
        bpf_spin_unlock(&st->lock);
        return TC_ACT_SHOT;
    }

    st->t_last = t_send;
    bpf_spin_unlock(&st->lock);

    skb->tstamp = t_send;
    return TC_ACT_OK;
}

// ==========================================
// Scenario B: Container Ingress (World -> Pod)
// ==========================================
SEC("tc/tbf_ingress")
int handle_tbf_ingress(struct __sk_buff* skb) {
    __u32 ifindex = skb->ifindex;

    // ... (rate_map lookup logic same as before) ...
    __u64* rate_bps = bpf_map_lookup_elem(&rate_map, &ifindex);
    if (!rate_bps || *rate_bps == 0)
        return TC_ACT_OK;

    struct tbf_state* st = bpf_map_lookup_elem(&tbf_state_map, &ifindex);
    if (!st)
        return TC_ACT_OK;

    // --- New: Read dynamic configuration ---
    __u64 horizon_ns, burst_bytes;
    get_global_config(&horizon_ns, &burst_bytes);

    __u64 rate = *rate_bps;
    __u64 now = bpf_ktime_get_ns();
    __u64 packet_len = skb->len;
    int ret = TC_ACT_OK;

    bpf_spin_lock(&st->lock);

    // --- Modified: Initialize using burst_bytes ---
    if (st->last_tstamp == 0) {
        st->last_tstamp = now;
        st->tokens = burst_bytes;
    }

    __u64 delta_ns = now - st->last_tstamp;
    if ((__s64)delta_ns < 0) [[clang::unlikely]]
        delta_ns = 0;

    // --- Modified: Calculate max fill time using burst_bytes ---
    // Time = (Bytes * 10^9) / Rate
    __u64 max_fill_time = (burst_bytes * NSEC_PER_SEC) / rate;

    if (delta_ns >= max_fill_time) {
        st->tokens = burst_bytes;
    } else {
        __u64 tokens_generated = (delta_ns * rate) / NSEC_PER_SEC;

        if (tokens_generated > 0) {
            st->tokens += tokens_generated;

            if (st->tokens > burst_bytes) {
                st->tokens = burst_bytes;
            }
            st->last_tstamp = now;
        }
    }

    if (st->tokens >= packet_len) {
        st->tokens -= packet_len;
        ret = TC_ACT_OK;
    } else {
        ret = TC_ACT_SHOT;
    }

    bpf_spin_unlock(&st->lock);

    return ret;
}
