// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define INGRESS 0
#define EGRESS 1
#define NANO_PER_SEC 1000000000ULL

#define ENABLE_PRINT 0

#if ENABLE_PRINT
#define kuro_debug(fmt, ...)                                                   \
  bpf_printk("[%d %s]: " fmt, __LINE__, __func__, ##__VA_ARGS__)

#else

#define kuro_debug(fmt, ...)

#endif /* ENABLE_PRINT */

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// token bucket
struct bucket_state {
  __u64 tokens;
  __u64 last_ns;

  struct bpf_spin_lock lock;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct bucket_state);
} bucket_state_map SEC(".maps");

struct bucket_rule {
  __u64 rate_bytes;
  __u64 burst_bytes;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct bucket_rule);
} bucket_rule_map SEC(".maps");

struct flow_counter {
  __u64 accepted_bytes;
  __u64 dropped_bytes;
  __u64 accepted_packets;
  __u64 dropped_packets;
};

struct { // send stats back to user-side
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32); // always 0
  __type(value, struct flow_counter);
  __uint(max_entries, 1);
} flow_counter_map SEC(".maps");

static __always_inline int check_limit(struct __sk_buff *skb) {

  __u32 key = 0;
  struct bucket_state *bucket = bpf_map_lookup_elem(&bucket_state_map, &key);
  if (bucket == NULL)
    return TC_ACT_OK;

  struct bucket_rule *rule = bpf_map_lookup_elem(&bucket_rule_map, &key);
  if (rule == NULL)
    return TC_ACT_OK;

  __u64 now = bpf_ktime_get_ns();
  __u32 skb_len = skb->len;
  int decision = TC_ACT_SHOT;

  kuro_debug("burst_bytes = %llu, rate_bytes = %llu", rule->burst_bytes,
             rule->rate_bytes);

  bpf_spin_lock(&bucket->lock);

  __u64 delta = now - bucket->last_ns;

  // add tokens to bucket
  if (delta > 0) {
    __u64 new_tokens;
    __u64 max_tokens = rule->burst_bytes;

    new_tokens = (delta * rule->rate_bytes) / NANO_PER_SEC; // may be overflow
    bucket->tokens += new_tokens;

    if (bucket->tokens > max_tokens) {
      bucket->tokens = max_tokens;
    }

    bucket->last_ns = now;
  }

  // consume tokens
  if (bucket->tokens >= skb_len) {
    bucket->tokens -= skb_len;
    decision = TC_ACT_OK;
  } else {
    decision = TC_ACT_SHOT;
  }

  bpf_spin_unlock(&bucket->lock);

  kuro_debug("decision = %d", decision);

  struct flow_counter *cnt = bpf_map_lookup_elem(&flow_counter_map, &key);
  if (cnt) {
    if (decision == TC_ACT_OK) {
      // accepted
      ++cnt->accepted_packets;
      cnt->accepted_bytes += skb_len;
    } else {
      // dropped
      ++cnt->dropped_packets;
      cnt->dropped_bytes += skb_len;
    }
  }

  kuro_debug("decision = %d", decision);

  return decision;
}

// main entry
SEC("tc") int gress(struct __sk_buff *skb) { return check_limit(skb); }
