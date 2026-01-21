// go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define NSEC_PER_SEC 1000000000ULL

// 100 Mbps
#define RATE_BPS 12500000ULL
// 50ms 最大延迟
#define MAX_DELAY_NS 50000000ULL

// === 修改点 1: 重命名结构体为 edt_state 以避免冲突 ===
struct edt_state {
  __u64 t_last;
  struct bpf_spin_lock lock;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct edt_state); // === 修改点 2 ===
} state_map SEC(".maps");

SEC("tc")
int simple_edt(struct __sk_buff *skb) {
  __u32 key = 0;
  // === 修改点 3 ===
  struct edt_state *st = bpf_map_lookup_elem(&state_map, &key);
  if (!st)
    return TC_ACT_OK;

  __u64 now = bpf_ktime_get_ns();
  __u64 len = skb->len;

  __u64 tx_cost = (len * NSEC_PER_SEC) / RATE_BPS;

  bpf_spin_lock(&st->lock);

  __u64 t_earliest = st->t_last;
  if (t_earliest < now) {
    t_earliest = now;
  }

  __u64 delay = t_earliest - now;
  if (delay > MAX_DELAY_NS) {
    bpf_spin_unlock(&st->lock);
    return TC_ACT_SHOT;
  }

  st->t_last = t_earliest + tx_cost;

  bpf_spin_unlock(&st->lock);

  if (t_earliest > now) {
    bpf_skb_set_tstamp(skb, t_earliest, BPF_SKB_TSTAMP_DELIVERY_MONO);
  }

  return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
