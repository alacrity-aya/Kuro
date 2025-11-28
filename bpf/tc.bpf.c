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

#define ENABLE_PRINT 1
#if ENABLE_PRINT
#define kuro_debug(fmt, ...)                                                   \
  bpf_printk("%d %s: " fmt, __LINE__, __func__, ##__VA_ARGS__)

#else
#define kuro_debug(fmt, ...)
#endif /* ENABLE_PRINT */

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/// ---------- Port Classification Key ----------

struct port_key {
  __u16 port; // host byte order port
};

typedef __u8 port_value; // 1 = target; 0 = other

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, struct port_key);
  __type(value, port_value);
} ports SEC(".maps");

/// ---------- Rate Limit Config (from userspace) ------------

struct rule {
  __u64 rate_limit_bps; // bits per sec
  __u64 time_scale_ms;  // millisecond, default = 100ms
  __u32 burst_bytes;
};

/// key = 0 target, key = 1 other
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 2);
  __type(key, __u32);
  __type(value, struct rule);
} rate_config_map SEC(".maps");

/// ---------- Bucket State -----------

struct bucket_state {
  __u64 tokens;
  __u64 last_ns;
  struct bpf_spin_lock lock;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 2);
  __type(key, __u32);
  __type(value, struct bucket_state);
} traffic_bucket SEC(".maps");

/// ---------- Statistics -----------

struct FlowCounter {
  __u64 accepted_bytes;
  __u64 dropped_bytes;
  __u64 accepted_packets;
  __u64 dropped_packets;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 2);
  __type(key, __u32);
  __type(value, struct FlowCounter);
} flow_stats SEC(".maps");

/// ---------- Token Bucket Logic ----------

static __always_inline int token_bucket_rate_limit(__u32 class_id,
                                                   __u32 skb_len) {
  struct rule *cfg = bpf_map_lookup_elem(&rate_config_map, &class_id);
  if (!cfg) {
    kuro_debug("failed to find config, class_id = %u", class_id);
    return TC_ACT_OK;
  }
  struct bucket_state *bucket = bpf_map_lookup_elem(&traffic_bucket, &class_id);
  if (!bucket) {
    kuro_debug("failed to find bucket, class_id = %u", class_id);
    return TC_ACT_OK;
  }

  __u64 now = bpf_ktime_get_ns();
  __u64 delta_ns = now - bucket->last_ns;

  const __u64 DEFAULT_TS_MS = 100;
  __u64 ts_ms = cfg->time_scale_ms ? cfg->time_scale_ms : DEFAULT_TS_MS;

  /* Convert delta to ms */
  __u64 delta_ms = delta_ns / 1000000ULL;

  /* Bytes per ms = (bps / 8) / 1000 */
  __u64 rate_bytes_per_ms = cfg->rate_limit_bps / 8 / 1000;

  /* Compute bucket capacity (bytes) */
  __u64 capacity_bytes = cfg->burst_bytes;
  if (capacity_bytes == 0) {
    capacity_bytes = rate_bytes_per_ms * ts_ms;
    if (capacity_bytes == 0 && rate_bytes_per_ms > 0) {
      capacity_bytes = 1; // ensure non-zero burst
    }
  }

  bpf_spin_lock(&bucket->lock);

  /* Refill tokens */
  if (delta_ms > 0) {
    if (delta_ms >= ts_ms) {
      bucket->tokens = capacity_bytes; // full
    } else {
      __u64 add = rate_bytes_per_ms * delta_ms;
      bucket->tokens += add;
      if (bucket->tokens > capacity_bytes)
        bucket->tokens = capacity_bytes;
    }
    bucket->last_ns = now;
  }

  int action;
  if (bucket->tokens >= skb_len) {
    bucket->tokens -= skb_len;
    action = TC_ACT_OK;
  } else {
    action = TC_ACT_SHOT;
  }

  bpf_spin_unlock(&bucket->lock);

  kuro_debug("token_bucket_rate_limit return %s",
             action == TC_ACT_OK ? "TC_ACT_OK" : "TC_ACT_SHOT");
  return action;
}

static __always_inline void update_stats(__u32 class_id, __u32 len, int act) {
  struct FlowCounter *st = bpf_map_lookup_elem(&flow_stats, &class_id);
  if (!st)
    return;

  kuro_debug("update_stats: act = %d", act);

  if (act == TC_ACT_OK) {
    st->accepted_bytes += len;
    st->accepted_packets++;
  } else {
    st->dropped_bytes += len;
    st->dropped_packets++;
  }
}

/// ---------- Packet Classification ----------

static __always_inline int check_limit(struct __sk_buff *skb, __u8 gress) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  __u32 len = skb->len;
  __u32 class_id = 1; // default other flow

  struct ethhdr *eth = data;
  if ((void *)eth + sizeof(*eth) > data_end)
    return TC_ACT_OK;

  if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
    goto APPLY;

  struct iphdr *ip = data + sizeof(*eth);
  if ((void *)ip + sizeof(*ip) > data_end)
    goto APPLY;

  __u32 ihl = ip->ihl * 4;
  if (ihl < sizeof(*ip))
    goto APPLY;

  __u16 port = 0;

  __u16 src_port = 0;
  __u16 dst_port = 0;

  if (ip->protocol == IPPROTO_TCP) {
    struct tcphdr *tcp = (void *)ip + ihl;
    if ((void *)tcp + sizeof(*tcp) > data_end)
      goto APPLY;
    src_port = bpf_ntohs(tcp->source);
    dst_port = bpf_ntohs(tcp->dest);
  } else if (ip->protocol == IPPROTO_UDP) {
    struct udphdr *udp = (void *)ip + ihl;
    if ((void *)udp + sizeof(*udp) > data_end)
      goto APPLY;
    src_port = bpf_ntohs(udp->source);
    dst_port = bpf_ntohs(udp->dest);
  } else {
    goto APPLY;
  }

  struct port_key k_src = {
      .port = src_port,
  };
  port_value *v_src = bpf_map_lookup_elem(&ports, &k_src);

  struct port_key k_dst = {
      .port = dst_port,
  };
  port_value *v_dst = bpf_map_lookup_elem(&ports, &k_dst);

  if ((v_src && *v_src == 1) || (v_dst && *v_dst == 1)) {
    class_id = 0;

    kuro_debug("Target HIT! src=%u dst=%u gress=%d", src_port, dst_port, gress);
  } else {
    class_id = 1; // other
  }

  int act;

APPLY:
  act = token_bucket_rate_limit(class_id, len);
  update_stats(class_id, len, act);
  kuro_debug("class_id = %u, act = %d", class_id, act);
  return act;
}

// main entry
SEC("tc") int gress(struct __sk_buff *skb) { return check_limit(skb, 0); }
