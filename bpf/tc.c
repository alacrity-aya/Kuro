#include "map.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1

static __always_inline __u32 get_ipv4(struct __sk_buff* skb, bool is_dest) {
    if (skb->protocol != bpf_htons(ETH_P_IP))
        return 0;

    // Ethernet header length = 14
    __u32 ip_offset = 14;
    struct iphdr iph;

    if (bpf_skb_load_bytes(skb, ip_offset, &iph, sizeof(struct iphdr)) < 0)
        return 0;

    if (is_dest)
        return iph.daddr;
    else
        return iph.saddr;
}

static __always_inline void* lookup_rule(void* map, __u32 ifindex, __u32 ip) {
    struct rule_key key;
    key.ifindex = ifindex;
    key.ipv4 = ip;

    void* rule = bpf_map_lookup_elem(map, &key);
    if (rule)
        return rule;

    key.ipv4 = 0;
    return bpf_map_lookup_elem(map, &key);
}

#define UPDATE_FLOW_COUNTER(gress, len, dropped) \
    do { \
        if (cnt) { \
            if ((dropped) == 0) { \
                cnt->gress##_packets++; \
                cnt->gress##_bytes += (len); \
            } else { \
                cnt->gress##_dropped_packets++; \
                cnt->gress##_dropped_bytes += (len); \
            } \
        } \
    } while (0)

static __always_inline void
__record_flow(__u32 ifindex, __u32 ipv4, __u32 len, int dropped, bool is_ingress) {
    struct rule_key key = { .ifindex = ifindex, .ipv4 = ipv4 };
    struct flow_counter* cnt = bpf_map_lookup_elem(&flow_counter_map, &key);

    //fallback to default counter
    if (!cnt) {
        kuro_debug("Flow miss specific: if=%u", ifindex);
        kuro_debug("... for ip=%x", ipv4);
        key.ipv4 = 0;
        cnt = bpf_map_lookup_elem(&flow_counter_map, &key);

        if (cnt) {
            kuro_debug("Flow hit default: if=%u", ifindex);
        } else {
            kuro_debug("FATAL: Flow miss ALL: if=%u", ifindex);
        }
    }

    if (is_ingress) {
        UPDATE_FLOW_COUNTER(rx, len, dropped);
    } else {
        UPDATE_FLOW_COUNTER(tx, len, dropped);
    }
}

#undef UPDATE_FLOW_COUNTER

static __always_inline void record_ingress(__u32 ifindex, __u32 ipv4, __u32 len, int dropped) {
    __record_flow(ifindex, ipv4, len, dropped, true);
}

static __always_inline void record_egress(__u32 ifindex, __u32 ipv4, __u32 len, int dropped) {
    __record_flow(ifindex, ipv4, len, dropped, false);
}

// return 0 = ok, 1 = drop
static __always_inline int
apply_limit(struct __sk_buff* skb, __u32 ifindex, __u32 ip, struct traffic_rule* rule) {
    struct rule_key key = { .ifindex = ifindex, .ipv4 = ip };
    struct bucket_state* bucket = bpf_map_lookup_elem(&bucket_state_map, &key);

    if (!rule) {
        return 0;
    }

    if (!bucket && ip != 0) {
        // use default rule
        key.ipv4 = 0;
        bucket = bpf_map_lookup_elem(&bucket_state_map, &key);
    }
    if (!bucket)
        return 0;

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

// upload
SEC("tc")
int ingress(struct __sk_buff* skb) {
    __u32 ifindex = skb->ifindex;
    __u32 dest_ip = get_ipv4(skb, true);

    // NetEm (Loss)
    struct netem_rule* netem_rule = lookup_rule(&netem_rule_map, ifindex, dest_ip);
    if (apply_loss(netem_rule) == 1) {
        record_ingress(ifindex, dest_ip, skb->len, 1); // Drop
        return TC_ACT_SHOT;
    }

    // Traffic Shaping (Limit)
    struct traffic_rule* traffic_rule = lookup_rule(&traffic_rule_map, ifindex, dest_ip);
    int dropped = apply_limit(skb, ifindex, dest_ip, traffic_rule);

    record_ingress(ifindex, dest_ip, skb->len, dropped); // Drop or Accept

    if (dropped)
        return TC_ACT_SHOT;
    return TC_ACT_OK;
}

// download
SEC("tc")
int egress(struct __sk_buff* skb) {
    //TODO: maybe we need apply_loss here
    //disinguish ingress loss and egress loss
    __u32 ifindex = skb->ifindex;
    __u32 src_ip = get_ipv4(skb, false);

    struct netem_rule* netem_rule = lookup_rule(&netem_rule_map, ifindex, src_ip);

    // NetEm (delay)
    apply_delay(skb, netem_rule);

    record_egress(ifindex, src_ip, skb->len, 0);

    return TC_ACT_OK;
}
