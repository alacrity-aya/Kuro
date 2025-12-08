// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

//      [TC ingress]
//           |
//           v
//  lookup(limit_rule_map)
//    |             |
//    |no rule      |has rule
//    v             v
// redirect      call check_limit()
//                  |
//          drop? → return SHOT
//                  |
//                  v
//               redirect

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define INGRESS 0
#define EGRESS 1

#define NANO_PER_SEC 1000000000ULL

#define ENABLE_PRINT 1

#if ENABLE_PRINT
#define kuro_debug(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)

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
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32); // iface index
  __type(value, struct bucket_state);
} bucket_state_map SEC(".maps"); // should be initialized in user-side

// flow rule
struct bucket_rule {
  __u64 rate_bytes;
  __u64 burst_bytes;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32); // iface_index
  __type(value, struct bucket_rule);
} bucket_rule_map SEC(".maps");

// count flow
struct flow_counter {
  __u64 accepted_bytes;
  __u64 dropped_bytes;
  __u64 accepted_packets;
  __u64 dropped_packets;
};

struct { // send stats back to user-side
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, __u32); // iface_index
  __type(value, struct flow_counter);
  __uint(max_entries, 1024);
} flow_counter_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __be32);  // dst ip
  __type(value, __u32); // iface_index
} redirect_map SEC(".maps");

// return 0 = ok, 1 = drop
static __always_inline int check_limit(struct __sk_buff *skb) {

  __u32 key = skb->ifindex;
  struct bucket_state *bucket = bpf_map_lookup_elem(&bucket_state_map, &key);
  if (bucket == NULL)
    return 0; // no limit → ok

  struct bucket_rule *rule = bpf_map_lookup_elem(&bucket_rule_map, &key);
  if (rule == NULL)
    return 0; // no limit → ok

  __u64 now = bpf_ktime_get_ns();
  __u32 skb_len = skb->len;
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

  // counter
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

static __always_inline void print_ip_addr(__be32 ip_addr) {
  __u32 host_ip = bpf_ntohl(ip_addr);
  __u32 o1 = (host_ip >> 24) & 0xFF;
  __u32 o2 = (host_ip >> 16) & 0xFF;
  __u32 o3 = (host_ip >> 8) & 0xFF;
  __u32 o4 = host_ip & 0xFF;

  kuro_debug("DIP {raw_be: %u, raw_host: %u, str: %d.%d.%d.%d}", ip_addr,
             host_ip, o1, o2, o3, o4);
}

// main entry
SEC("tc")
int gress(struct __sk_buff *skb) {
  __u32 in_ifindex = skb->ifindex;

  // check if there's rate limiting
  int dropped = check_limit(skb);
  if (dropped == 1) {
    return TC_ACT_SHOT;
  }

  // redirect according to dst ip
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_OK;

  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return TC_ACT_OK;

  struct iphdr *ip = data + sizeof(*eth);
  if ((void *)(ip + 1) > data_end)
    return TC_ACT_OK;

  __be32 dip = ip->daddr;

  __u32 *to_ifindex = bpf_map_lookup_elem(&redirect_map, &dip);
  if (!to_ifindex) {
    kuro_debug("[Failed] found to_ifindex");
    print_ip_addr(dip);
    return TC_ACT_OK;
  }

  long ret = bpf_redirect(*to_ifindex, 0);

  print_ip_addr(dip);
  kuro_debug("[Success] src index = %u, dst index = %u, ret = [%ld-%s]",
             skb->ifindex, to_ifindex, ret,
             ret == TCX_REDIRECT ? "REDIRECT" : "SHOT");

  return ret;
}
