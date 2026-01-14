#include "map.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

static __always_inline void record_ingress(__u32 key, __u32 len, int dropped) {
    struct flow_counter* cnt = bpf_map_lookup_elem(&flow_counter_map, &key);
    if (cnt) {
        if (dropped == 0) {
            cnt->rx_packets++;
            cnt->rx_bytes += len;
        } else {
            cnt->rx_dropped_packets++;
            cnt->rx_dropped_bytes += len;
        }
    }
}

static __always_inline void record_egress(__u32 key, __u32 len, int dropped) {
    struct flow_counter* cnt = bpf_map_lookup_elem(&flow_counter_map, &key);
    if (cnt) {
        if (dropped == 0) {
            cnt->tx_packets++;
            cnt->tx_bytes += len;
        } else {
            cnt->tx_dropped_packets++;
            cnt->tx_dropped_bytes += len;
        }
    }
}

// return 0 = ok, 1 = drop
static __always_inline int apply_limit(struct __sk_buff* skb, struct traffic_rule* rule) {
    __u32 key = skb->ifindex;
    struct bucket_state* bucket = bpf_map_lookup_elem(&bucket_state_map, &key);

    if (bucket == NULL)
        return 0;

    if (rule == NULL)
        return 0; // no limit

    __u64 now = bpf_ktime_get_ns();
    __u32 skb_len = skb->len;
    int dropped = 1;

    bpf_spin_lock(&bucket->lock);

    __u64 delta = now - bucket->last_ns;

    if (delta > 0) {
        __u64 max_tokens = rule->burst_bytes;
        __u64 new_tokens = (delta * rule->rate_bytes) / NSEC_PER_SEC;

        bucket->tokens += new_tokens;

        if (bucket->tokens > max_tokens)
            bucket->tokens = max_tokens;

        bucket->last_ns = now;
    }

    if (bucket->tokens >= skb_len) {
        bucket->tokens -= skb_len;
        dropped = 0;
    }

    bpf_spin_unlock(&bucket->lock);
    kuro_debug("drop = %s", dropped == 0 ? "ok" : "drop");

    return dropped;
}

static __always_inline void apply_delay(struct __sk_buff* skb, struct netem_rule* rule) {
    if (!rule) {
        return;
    }

    __u64 final_delay_ns = rule->delay_ms * NSEC_PER_MSEC;

    if (rule->jitter_ms > 0) {
        __u64 range_ms = 2ULL * rule->jitter_ms;
        __u64 rand_32 = bpf_get_prandom_u32();

        // (rand_32 * range_ms) >> 32 == rand_32 % range_ms
        __u64 jitter_offset_ms = (rand_32 * range_ms) >> 32;

        __u64 total_ms = rule->delay_ms + jitter_offset_ms;
        if (total_ms > rule->jitter_ms) {
            final_delay_ns = (total_ms - rule->jitter_ms) * NSEC_PER_MSEC;
        } else {
            final_delay_ns = 0;
        }
    }

    if (final_delay_ns > 0) {
        __u64 now = bpf_ktime_get_ns();

        __u64 target_tstamp = now + final_delay_ns;

        if (target_tstamp < now)
            target_tstamp = now;

        bpf_skb_set_tstamp(skb, target_tstamp, BPF_SKB_TSTAMP_DELIVERY_MONO);
    }

    return;
}

// Apply netem rule:
static __always_inline int apply_loss(struct netem_rule* rule) {
    if (rule != NULL && rule->loss_threshold != 0) {
        if (bpf_get_prandom_u32() < rule->loss_threshold) {
            kuro_debug("Packet lost due to netem rule.");
            return 1;
        }
    }
    kuro_debug("Packet passed");
    return 0;
}

SEC("tc")
int ingress(struct __sk_buff* skb) {
    __u32 key = skb->ifindex;

    // NetEm (Loss)
    struct netem_rule* netem_rule = bpf_map_lookup_elem(&netem_rule_map, &key);
    if (apply_loss(netem_rule) == 1) {
        record_ingress(key, skb->len, 1); // Drop
        return TC_ACT_SHOT;
    }

    // Traffic Shaping (Limit)
    struct traffic_rule* traffic_rule = bpf_map_lookup_elem(&traffic_rule_map, &key);
    int dropped = apply_limit(skb, traffic_rule);

    record_ingress(key, skb->len, dropped); // Drop or Accept

    if (dropped)
        return TC_ACT_SHOT;
    return TC_ACT_OK;
}

SEC("tc")
int egress(struct __sk_buff* skb) {
    //TODO: maybe we need apply_loss here
    //ingress loss and egress loss
    __u32 key = skb->ifindex;

    struct netem_rule* netem_rule = bpf_map_lookup_elem(&netem_rule_map, &key);

    apply_delay(skb, netem_rule);

    record_egress(key, skb->len, 0);

    return TC_ACT_OK;
}
