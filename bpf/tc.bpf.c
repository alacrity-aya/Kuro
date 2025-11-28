// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP 0x0800
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define NANO_PER_SEC 1000000000ULL

#define INGRESS 0
#define EGRESS 1

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// --- Configuration Structs ---

struct rule {
  __u64 rate_limit_bps; // Rate limit in Bits per second
  __u64 time_scale;
  __u32 burst_bytes; // Burst size in Bytes
  __u8 gress;        // 0 INGRESS; 1 EGRESS; 2 UNKNOWN
};

// Map: Configuration (Input from User Space)
// Key 0: Simulation Traffic, Key 1: Other Traffic
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 2);
  __type(key, __u32);
  __type(value, struct rule);
} rate_config_map SEC(".maps");

// --- Runtime State Structs ---

// Token Bucket State with Spinlock for concurrency safety
struct BucketState {
  __u64 tokens;              // Current tokens in Bytes
  __u64 last_ns;             // Last update timestamp
  struct bpf_spin_lock lock; // Mandatory for atomic updates
};

// Map: Token Bucket State (Internal)
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 2);
  __type(key, __u32);
  __type(value, struct BucketState);
} traffic_bucket SEC(".maps");

// Statistics Counter
struct FlowCounter {
  __u64 accepted_bytes;
  __u64 dropped_bytes;
  __u64 accepted_packets;
  __u64 dropped_packets;
};

// Map: Statistics (Output to User Space)
// Use PERCPU_ARRAY for high performance statistics
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 2);
  __type(key, __u32);
  __type(value, struct FlowCounter);
} flow_stats SEC(".maps");

// --- Helper Functions ---

static __always_inline int token_bucket_rate_limit(__u32 key, __u32 skb_len) {
  // 1. Lookup Configuration
  struct rule *cfg = bpf_map_lookup_elem(&rate_config_map, &key);
  if (!cfg || cfg->rate_limit_bps == 0) {
    return TC_ACT_OK; // No limit set, pass
  }

  // 2. Lookup Bucket State
  struct BucketState *bucket = bpf_map_lookup_elem(&traffic_bucket, &key);
  if (!bucket) {
    return TC_ACT_OK; // Should not happen if map is init correctly
  }

  __u64 now = bpf_ktime_get_ns();
  int decision = TC_ACT_SHOT; // Default to drop

  // 3. Critical Section: Update Tokens
  bpf_spin_lock(&bucket->lock);

  __u64 delta = now - bucket->last_ns;
  __u64 capacity_bytes = cfg->burst_bytes;
  __u64 rate_bytes_per_sec = cfg->rate_limit_bps / 8;

  // Replenish tokens
  if (delta > 0) {
    // Avoid overflow for very large delta
    if (delta >= NANO_PER_SEC) {
      bucket->tokens = capacity_bytes;
    } else {
      // tokens = (delta_ns * rate_bytes/sec) / 10^9
      __u64 new_tokens = (delta * rate_bytes_per_sec) / NANO_PER_SEC;
      bucket->tokens += new_tokens;
      if (bucket->tokens > capacity_bytes) {
        bucket->tokens = capacity_bytes;
      }
    }
    bucket->last_ns = now;
  }

  // Consume tokens
  if (bucket->tokens >= skb_len) {
    bucket->tokens -= skb_len;
    decision = TC_ACT_OK;
  } else {
    // Not enough tokens
    decision = TC_ACT_SHOT;
  }

  bpf_spin_unlock(&bucket->lock);
  return decision;
}

static __always_inline void update_stats(__u32 key, __u32 len, int action) {
  struct FlowCounter *stats = bpf_map_lookup_elem(&flow_stats, &key);
  if (stats) {
    if (action == TC_ACT_OK) {
      stats->accepted_bytes += len;
      stats->accepted_packets += 1;
    } else {
      stats->dropped_bytes += len;
      stats->dropped_packets += 1;
    }
  }
}

static __always_inline int check_limit(struct __sk_buff *skb, __u8 gress) {

  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;
  __u32 len = skb->len;
  __u32 key = 1; // Default to "Other Traffic" (Key 1)

  // Basic sanity check
  if (data == NULL)
    return TC_ACT_OK;

  // 1. Packet Parsing to determine Traffic Class
  struct ethhdr *eth = data;
  if ((void *)eth + sizeof(*eth) > data_end)
    return TC_ACT_OK;

  if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
    struct iphdr *ip = (void *)eth + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
      return TC_ACT_OK;

    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(*ip) || (void *)ip + ip_hdr_len > data_end)
      return TC_ACT_OK;

    // TCP
    if (ip->protocol == IPPROTO_TCP) {
      struct tcphdr *tcp = (void *)ip + ip_hdr_len;
      if ((void *)tcp + sizeof(*tcp) > data_end)
        return TC_ACT_OK;

      // Check for Simulation Port (8888)
      if (bpf_ntohs(tcp->dest) == 8888) {
        key = 0; // Key 0: Simulation Traffic
      }
    }

    // UDP
    if (ip->protocol == IPPROTO_UDP) {
      struct udphdr *udp = (void *)ip + ip_hdr_len;
      if ((void *)udp + sizeof(*udp) > data_end)
        return TC_ACT_OK;
      if (bpf_ntohs(udp->dest) == 8888) {
        key = 0;
      }
    }
  }

  // 2. Apply Rate Limiting
  int action = token_bucket_rate_limit(key, len);

  // 3. Update Statistics
  update_stats(key, len, action);

  return action;
}

// --- Main Program ---

SEC("tc") int egress(struct __sk_buff *skb) { return check_limit(skb, EGRESS); }

SEC("tc") int ingress(struct __sk_buff *skb) {
  return check_limit(skb, INGRESS);
}
