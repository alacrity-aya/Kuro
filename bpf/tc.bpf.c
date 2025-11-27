// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/
#define TC_ACT_OK 0

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// --- 定义令牌桶配置结构 ---
// 这里的配置可以通过 BPF Map 从用户态传入
struct rate_config {
  __u64 rate_limit_bps; // 限制速率 (Bits per second)
  __u32 burst_bytes;    // 桶深 (Bytes)
};

// --- 定义状态 Map ---
// 这是一个数组 Map，用于存储两个桶的配置:
// 键 0: 仿真流量配置
// 键 1: 其他流量配置
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 2);
  __type(key, __u32);
  __type(value, struct rate_config);
} rate_config_map SEC(".maps");

SEC("tc")
int sim_tbf_egress(struct __sk_buff *skb) {
  // 默认通过 (PASS)
  // 在真正的 TBF 逻辑实现之前，我们先确保程序能成功加载并运行

  // 1. 流量分类：检查数据包是否为仿真流量 (例如：目标端口 8888)
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;

  struct ethhdr *eth = data;
  if (data + sizeof(*eth) > data_end) {
    return TC_ACT_OK; // 非法包，通过
  }

  if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end) {
      return TC_ACT_OK;
    }

    if (ip->protocol == IPPROTO_TCP) {
      struct tcphdr *tcp = data + sizeof(*eth) + (ip->ihl * 4);
      if (data + sizeof(*eth) + (ip->ihl * 4) + sizeof(*tcp) > data_end) {
        return TC_ACT_OK;
      }

      // 假设仿真流量使用目标端口 8888
      if (bpf_ntohs(tcp->dest) == 8888) {
        // 是仿真流量
        // TODO: 在这里添加 eBPF TBF 逻辑，并使用 rate_config_map[0] 的配置

        // 暂时打印调试信息 (注意：bpf_printk 只用于调试)
        // bpf_printk("Simulation traffic detected!");

        // 暂时放行所有流量
        return TC_ACT_OK;
      }
    }
  }

  // 2. 不是仿真流量 (其他业务流量)
  // TODO: 在这里添加 eBPF TBF 逻辑，并使用 rate_config_map[1] 的配置

  return TC_ACT_OK;
}
