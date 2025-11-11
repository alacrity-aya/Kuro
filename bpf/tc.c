#define __TARGET_ARCH_x86
#include "common.h"
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "GPL";

#define EGRESS 1
#define INGRESS 0

/* Netfilter constants kept for compatibility in rule semantics */
#define NF_INET_LOCAL_IN 1
#define NF_INET_LOCAL_OUT 3

/* Return codes: map NF_* semantics to tc actions at the end */
#ifndef TC_ACT_OK
    #define TC_ACT_OK 0
#endif
#ifndef TC_ACT_SHOT
    #define TC_ACT_SHOT 2
#endif

struct ProcInfo {
    __u32 pid;
    char comm[16];
};

struct net_group {
    __u32 ip;
    __u16 port;
    __u8 protocol;
};

struct process_rule {
    __u32 target_pid;
    __u64 rate_bps;
    __u8 gress; /* EGRESS or INGRESS */
    __u32 time_scale;
};

struct message_get {
    __u64 instance_rate_bps;
    __u64 rate_bps;
    __u64 peak_rate_bps;
    __u64 smoothed_rate_bps;
    struct ProcInfo proc;
    __u64 timestamp;
};

/* maps: keep same definitions as original */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct sock*);
    __type(value, struct ProcInfo);
    __uint(max_entries, 20000);
} sock_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct process_rule);
    __uint(max_entries, 1024);
} process_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct rate_bucket);
    __uint(max_entries, 1024);
} buckets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct flow_rate_info));
    __uint(max_entries, 1);
} flow_rate_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct net_group);
    __type(value, struct ProcInfo);
    __uint(max_entries, 20000);
} tuple_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} local_ip_map SEC(".maps");

/* Helpers: use __sk_buff for TC. We reuse bpf_dynptr_from_skb as before.
   Note: in TC skb points to packet starting at ethernet header. */

/* load UDP header at offset (from start of packet) */
static struct udphdr* udp_hdr(struct __sk_buff* skb, u32 offset) {
    struct bpf_dynptr ptr;
    struct udphdr udph = {};
    if ((u64)skb->len <= offset)
        return NULL;

    if (bpf_dynptr_from_skb((struct __sk_buff*)skb, 0, &ptr))
        return NULL;

    return bpf_dynptr_slice(&ptr, offset, &udph, sizeof(udph));
}

/* load TCP header at offset (from start of packet) */
static struct tcphdr* tcp_hdr(struct __sk_buff* skb, u32 offset) {
    struct bpf_dynptr ptr;
    struct tcphdr tcph = {};
    if ((u64)skb->len <= offset)
        return NULL;

    if (bpf_dynptr_from_skb((struct __sk_buff*)skb, 0, &ptr))
        return NULL;

    return bpf_dynptr_slice(&ptr, offset, &tcph, sizeof(tcph));
}

/* load IP header at offset (from start of packet) */
static struct iphdr* ip_hdr(struct __sk_buff* skb, u32 offset) {
    struct bpf_dynptr ptr;
    struct iphdr iph = {};

    if ((u64)skb->len <= offset + sizeof(iph))
        return NULL;

    if (bpf_dynptr_from_skb((struct __sk_buff*)skb, 0, &ptr))
        return NULL;

    return bpf_dynptr_slice(&ptr, offset, &iph, sizeof(iph));
}

static __inline void send_message(struct message_get* mes) {
    struct message_get* e;

    e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
    if (!e) {
        return;
    }
    *e = *mes;
    e->timestamp = start_to_now_ns();

    bpf_ringbuf_submit(e, 0);
}

/* parse packet in TC context:
   - skb points to Ethernet header start
   - direction: EGRESS or INGRESS (decides which ip/port to extract)
   - tuple: output net_group (ip, port, protocol)
   returns true on success */
static __attribute__((noinline)) bool
parse_skb_tc(struct __sk_buff* skb, __u8 direction, struct net_group* tuple) {
    struct iphdr* iph;
    struct udphdr* udph;
    struct tcphdr* tcph;
    unsigned int iphl;
    const u32 eth_hdr_len = sizeof(struct ethhdr);
    u32 ip_offset = eth_hdr_len;

    if ((u64)skb->len < eth_hdr_len + 20) { /* at least eth + ip */
        return false;
    }

    iph = ip_hdr(skb, ip_offset);
    if (!iph)
        return false;

    if (iph->version != 4)
        return false;

    iphl = iph->ihl * 4;
    if (iph->ihl < 5)
        return false;

    if ((u64)skb->len <= ip_offset + iphl)
        return false;

    if (iph->protocol == IPPROTO_UDP) {
        if ((u64)skb->len < ip_offset + iphl + sizeof(struct udphdr))
            return false;

        udph = udp_hdr(skb, ip_offset + iphl);
        if (!udph)
            return false;

        tuple->protocol = IPPROTO_UDP;
        if (direction == EGRESS) {
            tuple->ip = bpf_ntohl(iph->saddr);
            tuple->port = bpf_ntohs(udph->source);
        } else {
            tuple->ip = bpf_ntohl(iph->daddr);
            tuple->port = bpf_ntohs(udph->dest);
        }
    } else if (iph->protocol == IPPROTO_TCP) {
        if ((u64)skb->len < ip_offset + iphl + sizeof(struct tcphdr))
            return false;

        tcph = tcp_hdr(skb, ip_offset + iphl);
        if (!tcph)
            return false;

        tuple->protocol = IPPROTO_TCP;
        if (direction == EGRESS) {
            tuple->ip = bpf_ntohl(iph->saddr);
            tuple->port = bpf_ntohs(tcph->source);
        } else {
            tuple->ip = bpf_ntohl(iph->daddr);
            tuple->port = bpf_ntohs(tcph->dest);
        }
    } else {
        return false;
    }

    return true;
}

/* save_sock and the kprobes remain useful: they populate sock_map & tuple_map
   same as original implementation (no change necessary) */
static void save_sock(struct socket* sock) {
    struct sock* sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return;

    struct ProcInfo proc = {};
    proc.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(proc.comm, sizeof(proc.comm));

    bpf_map_update_elem(&sock_map, (void*)&sk, &proc, BPF_ANY);
}

SEC("kprobe/security_socket_recvmsg")
int BPF_KPROBE(security_socket_recvmsg, struct socket* sock, struct msghdr* msg) {
    save_sock(sock);

    struct sock* sk = BPF_CORE_READ(sock, sk);
    if (sk) {
        __u16 skproto = BPF_CORE_READ(sk, sk_protocol);
        if (skproto != IPPROTO_UDP) {
            return 0;
        }

        __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_num);

        if (daddr == 0) {
            __u32 key = 0;
            __u32* local_ip = bpf_map_lookup_elem(&local_ip_map, &key);
            if (local_ip) {
                daddr = bpf_ntohl(*local_ip);
            }
        }

        struct net_group key = {};
        key.ip = bpf_ntohl(daddr);
        key.port = bpf_ntohs(dport);
        key.protocol = IPPROTO_UDP;

        struct ProcInfo proc = {};
        proc.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(proc.comm, sizeof(proc.comm));
        bpf_map_update_elem(&tuple_map, &key, &proc, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/security_socket_sendmsg")
int BPF_KPROBE(security_socket_sendmsg, struct socket* sock) {
    if (!sock) {
        return 0;
    }

    save_sock(sock);
    return 0;
}

/* Common handler used by both ingress and egress TC programs.
   Returns TC_ACT_OK to accept, TC_ACT_SHOT to drop. */
static __attribute__((noinline)) int tc_handle(struct __sk_buff* skb, __u8 direction) {
    struct process_rule* rule;
    struct message_get mes = { 0 };
    __u32 rule_key = 0;

    rule = bpf_map_lookup_elem(&process_rules, &rule_key);
    if (!rule) {
        return TC_ACT_OK;
    }

    /* rule->gress uses NF_INET_LOCAL_OUT (egress) semantics in original.
       Keep same meaning: if mismatch, accept. */
    if (rule->gress == EGRESS && direction != EGRESS)
        return TC_ACT_OK;
    if (rule->gress == INGRESS && direction != INGRESS)
        return TC_ACT_OK;

    /* parse packet to get tuple */
    struct net_group key = {};
    bool ok = parse_skb_tc(skb, direction, &key);
    if (!ok)
        return TC_ACT_OK;

    /* try to find proc info:
       - for ingress UDP we try tuple_map (no skb->sk)
       - otherwise try sock_map (if skb has associated sk pointer) */
    struct ProcInfo* proc = NULL;

    /* attempt to get skb->sk if present */
    volatile struct bpf_sock* pre_sk = BPF_CORE_READ(skb, sk);

    if (direction == INGRESS && key.protocol == IPPROTO_UDP) {
        proc = bpf_map_lookup_elem(&tuple_map, &key);
    } else {
        if (!pre_sk) {
            /* fall back to tuple lookup if no sk pointer */
            proc = bpf_map_lookup_elem(&tuple_map, &key);
        } else {
            struct sock* sk_ptr = (struct sock*)pre_sk;
            proc = bpf_map_lookup_elem(&sock_map, (void*)&sk_ptr);
        }
    }

    if (!proc)
        return TC_ACT_OK;

    __u32 pid = proc->pid;
    if (pid == 0)
        return TC_ACT_OK;

    if (rule->target_pid != proc->pid)
        return TC_ACT_OK;

    __u64 now = bpf_ktime_get_ns();
    __u32 flow_key = 1;
    struct flow_rate_info* info = bpf_map_lookup_elem(&flow_rate_stats, &flow_key);
    if (!info) {
        struct flow_rate_info new_flow = { .window_start_ns = now,
                                           .total_bytes = skb->len,
                                           .packet_bytes = skb->len,
                                           .last_ns = now,
                                           .instance_rate_bps = 0,
                                           .rate_bps = 0,
                                           .peak_rate_bps = 0,
                                           .smooth_rate_bps = 0 };
        bpf_map_update_elem(&flow_rate_stats, &flow_key, &new_flow, BPF_ANY);
    }
    info = bpf_map_lookup_elem(&flow_rate_stats, &flow_key);
    if (info) {
        update_flow_rate(info, skb->len);
        mes.rate_bps = info->rate_bps;
        mes.instance_rate_bps = info->instance_rate_bps;
        mes.peak_rate_bps = info->peak_rate_bps;
        mes.smoothed_rate_bps = info->smooth_rate_bps;
    }

    send_message(&mes);

    __u64 bucket_key = proc->pid;
    struct rate_limit rate = { .bucket_key = &bucket_key,
                               .buckets = &buckets,
                               .packet_len = skb->len,
                               .rate_bps = rule->rate_bps,
                               .time_scale = rule->time_scale };

    if (rate_limit_check(&rate) == ACCEPT) {
        return TC_ACT_OK;
    }

    return TC_ACT_SHOT;
}

/* TC egress program: attach to device egress */
SEC("tc_egress")
int tc_egress_prog(struct __sk_buff* skb) {
    return tc_handle(skb, EGRESS);
}

/* TC ingress program: attach to device ingress */
SEC("tc_ingress")
int tc_ingress_prog(struct __sk_buff* skb) {
    return tc_handle(skb, INGRESS);
}
