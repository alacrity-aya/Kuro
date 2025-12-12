// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP 0x0800
#define ETH_P_ARP 0x0806

#define NANO_PER_SEC 1000000000ULL

#define ENABLE_PRINT 1

#if ENABLE_PRINT
#define kuro_debug(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define kuro_debug(fmt, ...)
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct bucket_state {
  __u64 tokens;
  __u64 last_ns;
  struct bpf_spin_lock lock;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);
  __type(value, struct bucket_state);
} bucket_state_map SEC(".maps");

struct bucket_rule {
  __u64 rate_bytes;
  __u64 burst_bytes;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);
  __type(value, struct bucket_rule);
} bucket_rule_map SEC(".maps");

struct flow_counter {
  __u64 accepted_bytes;
  __u64 dropped_bytes;
  __u64 accepted_packets;
  __u64 dropped_packets;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, __u32);
  __type(value, struct flow_counter);
  __uint(max_entries, 1024);
} flow_counter_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __u32);   // host-endian ip (or be32, see note below)
  __type(value, __u32); // iface_index
} redirect_map SEC(".maps");

// --- Helper Functions ---

static __always_inline int check_limit(struct xdp_md *ctx) {
  __u32 key = ctx->ingress_ifindex;

  struct bucket_state *bucket = bpf_map_lookup_elem(&bucket_state_map, &key);
  if (!bucket)
    return 0;

  struct bucket_rule *rule = bpf_map_lookup_elem(&bucket_rule_map, &key);
  if (!rule)
    return 0;

  __u64 now = bpf_ktime_get_ns();
  __u64 skb_len = (__u64)(ctx->data_end - ctx->data);
  int dropped = 1;

  bpf_spin_lock(&bucket->lock);

  __u64 delta = now - bucket->last_ns;
  if (delta > 0) {
    __u64 max_tokens = rule->burst_bytes;
    __u64 new_tokens = (delta * rule->rate_bytes) / NANO_PER_SEC;
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

  // Update stats
  struct flow_counter *cnt = bpf_map_lookup_elem(&flow_counter_map, &key);
  if (cnt) {
    if (dropped == 0) {
      cnt->accepted_packets++;
      cnt->accepted_bytes += skb_len;
    } else {
      cnt->dropped_packets++;
      cnt->dropped_bytes += skb_len;
    }
  }

  return dropped;
}

struct arp_eth_ipv4 {
  __be16 ar_hrd;
  __be16 ar_pro;
  __u8 ar_hln;
  __u8 ar_pln;
  __be16 ar_op;
  unsigned char ar_sha[6];
  __be32 ar_sip;
  unsigned char ar_tha[6];
  __be32 ar_tip;
} __attribute__((packed));

static __always_inline int handle_arp(struct xdp_md *ctx, struct ethhdr *eth,
                                      void *data_end) {
  struct arp_eth_ipv4 *arp = (void *)(eth + 1);

  if ((void *)(arp + 1) > data_end)
    return XDP_PASS;

  if (arp->ar_pro != bpf_htons(ETH_P_IP) || arp->ar_pln != 4)
    return XDP_PASS;

  // NOTE: endian
  __be32 target_ip = bpf_htonl(arp->ar_tip);
  __u32 *to_ifindex = bpf_map_lookup_elem(&redirect_map, &target_ip);

  if (!to_ifindex) {
    return XDP_PASS;
  }

  kuro_debug("XDP Redirect ARP for %x to %d", target_ip, *to_ifindex);

  // XDP Redirect
  return bpf_redirect(*to_ifindex, 0);
}

// --- Main Program ---

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
  if (check_limit(ctx) == 1) {
    return XDP_DROP;
  }

  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return XDP_PASS;

  if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
    return handle_arp(ctx, eth, data_end);
  }

  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_PASS;

  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end)
    return XDP_PASS;

  // NOTE: endian
  __u32 dip = bpf_htonl(ip->daddr);

  __u32 *to_ifindex = bpf_map_lookup_elem(&redirect_map, &dip);
  if (!to_ifindex) {
    return XDP_PASS;
  }

  kuro_debug("XDP Redirect IP %x to %d", dip, *to_ifindex);

  return bpf_redirect(*to_ifindex, 0);
}
