#pragma once

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define ETH_P_IP 0x0800  /* Internet Protocol packet	*/
#define ETH_P_ARP 0x0806 /* Address Resolution packet	*/

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define INGRESS 0
#define EGRESS 1

#define NSEC_PER_SEC 1000000000ULL
#define NSEC_PER_MSEC 1000000ULL

#define ENABLE_PRINT 1

#if ENABLE_PRINT
#define kuro_debug(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)

#else

#define kuro_debug(fmt, ...)

#endif /* ENABLE_PRINT */

static __always_inline void print_ip_addr(__be32 ip_addr) {

#if ENABLE_PRINT

  __u32 host_ip = bpf_ntohl(ip_addr);
  __u32 o1 = (host_ip >> 24) & 0xFF;
  __u32 o2 = (host_ip >> 16) & 0xFF;
  __u32 o3 = (host_ip >> 8) & 0xFF;
  __u32 o4 = host_ip & 0xFF;

  kuro_debug("ip {raw_be: %u, raw_host: %u, str: %u.%u.%u.%u}", ip_addr,
             host_ip, o1, o2, o3, o4);

#endif // ENABLE_PRINT
}

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

// traffic rule
struct netem_rule {
  __u32 loss_threshold;
  __u64 jitter_ms;
  __u64 delay_ms;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32); // iface_index
  __type(value, struct netem_rule);
} netem_rule_map SEC(".maps");

// traffic rule
struct traffic_rule {
  __u64 rate_bytes;
  __u64 burst_bytes;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32); // iface_index
  __type(value, struct traffic_rule);
} traffic_rule_map SEC(".maps");

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

// redirct packets
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __u32);   // host-endian ip
  __type(value, __u32); // iface_index
} redirect_map SEC(".maps");

// receive vxlan index from user-side
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);   // always 0
  __type(value, __u32); // vxlan iface
} vxlan_map SEC(".maps");

// TODO: bypass map
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32); // ip addr passed by
  __type(value, __u32);
} bypass_map SEC(".maps");
