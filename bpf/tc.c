#include "include/helper.h"
#include "include/log.h"
#include "include/map.h"

// =============================================================
// Constant Definitions
// =============================================================

// TODO: these constant variables should be configurable

// Burst Allowance: 5ms
// Allows simulation traffic a small burst after an idle period (e.g., TCP handshake or ACKs).
// This avoids excessively high initial latency caused by strict pacing.
#define BURST_WINDOW_NS (2ULL * 1000000ULL)

// Sys Traffic Latency Offset: 3ms
// Artificial delay added to "System" (business) traffic.
// Purpose: In the FQ (Fair Queueing) scheduler of the host physical NIC,
// the timestamp for Sys traffic will always be 3ms later than Sim traffic.
// Result: As long as Sim traffic isn't severely backlogged, it will always be prioritized.
#define SYS_LATENCY_OFFSET_NS (3ULL * 1000000ULL)

// =============================================================
// Helper Functions
// =============================================================

/**
 * throttle_flow - EDT (Earliest Departure Time) Rate Limiting Core Logic
 *
 * This function implements the EDT algorithm to enforce precise bandwidth limits
 * by scheduling packet departure times. Unlike token bucket approaches, EDT
 * provides smoother traffic pacing by calculating the earliest time each packet
 * can be transmitted without exceeding the configured rate.
 *
 * Algorithm Overview:
 * 1. Calculate transmission time for current packet based on scaled cost
 * 2. Apply burst window allowance to handle idle periods gracefully
 * 3. Schedule packet departure time (t_send) based on last transmission
 * 4. Drop packet if scheduled time exceeds horizon (queue overflow protection)
 * 5. Update skb->tstamp for the kernel's FQ scheduler to enforce
 *
 * Burst Window Logic:
 * - If the flow was idle for longer than BURST_WINDOW_NS, we reset t_last
 *   to (now - BURST_WINDOW_NS), allowing a small burst to catch up.
 * - This prevents excessive latency spikes after idle periods (e.g., TCP ACKs).
 *
 * @skb:           Socket buffer containing the packet to throttle
 * @cost_per_byte_scaled: Scaled transmission cost per byte.
 *                        Formula: (NSEC_PER_SEC * 8 * 65536) / bandwidth_bps
 *                        Zero value disables rate limiting (pass-through).
 * @state_map:     BPF map containing EDT state entries (struct edt_state)
 * @target_idx:    Key into state_map, typically encoded as:
 *                  ifindex * 2 + traffic_type (0=sys, 1=sim)
 * @now:           Current kernel timestamp in nanoseconds
 * @horizon_ns:    Maximum scheduling horizon. Packets scheduled beyond
 *                  (now + horizon_ns) are dropped to prevent queue overflow.
 *
 * Return: TC_ACT_OK on success (packet scheduled), TC_ACT_SHOT on drop (overflow)
 */
static __always_inline int throttle_flow(
    struct __sk_buff* skb,
    __u64 cost_per_byte_scaled,
    void* state_map,
    __u32 target_idx,
    __u64 now,
    __u64 horizon_ns
) {
    if (cost_per_byte_scaled == 0)
        return TC_ACT_OK; // No Limit

    struct edt_state* st = bpf_map_lookup_elem(state_map, &target_idx);
    if (!st)
        return TC_ACT_OK;

    __u64 packet_len = skb->len;
    __u64 packet_time_ns = (packet_len * cost_per_byte_scaled) >> 16;
    __u64 t_send;

    bpf_spin_lock(&st->lock);
    __u64 t_last = st->t_last;
    __u64 burst_start = (now > BURST_WINDOW_NS) ? (now - BURST_WINDOW_NS) : 0;

    if (t_last < burst_start)
        t_last = burst_start;
    t_send = t_last + packet_time_ns;

    if (unlikely(t_send > now + horizon_ns)) {
        bpf_spin_unlock(&st->lock);
        return TC_ACT_SHOT; // Queue Overflow
    }

    st->t_last = t_send;
    bpf_spin_unlock(&st->lock);

    skb->tstamp = t_send;
    return TC_ACT_OK;
}

// =============================================================
// Scenario 1: Download Control (Host -> Pod)
// Hook Point: Host Veth Interface -> Egress
// Logic: Determine if Src IP belongs to a Sim node
// =============================================================
SEC("tc/edt_download")
int handle_edt_download(struct __sk_buff* skb) {
    __u64 now = bpf_ktime_get_ns();
    __u32 ifindex = skb->ifindex;

    // kuro_debug("handle_edt_download: ifindex=%u, pkt_len=%u", ifindex, skb->len);

    if (unlikely(ifindex >= MAX_IFINDEX_CAP))
        return TC_ACT_OK;
    struct io_rate* rates = bpf_map_lookup_elem(&rate_map, &ifindex);
    if (!rates)
        return TC_ACT_OK;

    // 1. Parse IP and Ports
    __u32 src_ip = 0;
    __u32 dst_ip = 0;
    if (unlikely(!parse_ipv4(skb, &src_ip, &dst_ip)))
        return TC_ACT_OK;

    __u16 src_port = 0;
    __u16 dst_port = 0;
    parse_ports(skb, &src_port, &dst_port);

    // 2. Traffic Classification
    int is_sim_traffic = 0;

    // A. Port Bypass (Escape)
    if (is_system_port(src_port) || is_system_port(dst_port)) {
        is_sim_traffic = 0;
    }
    // B. Identity Verification (Verify if sender is part of the topology)
    else {
        // Build Key: {Src=Sender, Dst=Receiver(Self)}
        struct policy_key key;
        key.src_ip = src_ip;
        key.dst_ip = dst_ip;

        // If a policy is found, it indicates a predefined simulation link
        void* policy_exists = bpf_map_lookup_elem(&topology_policy_map, &key);
        if (policy_exists) {
            is_sim_traffic = 1;
        } else {
            is_sim_traffic = 0;
        }
    }

    // 3. Configuration Parameters
    __u64 target_cost = 0;
    __u64 horizon_ns = 0;
    __u64 offset_ns = 0;
    get_global_config(&horizon_ns);

    if (is_sim_traffic) {
        // [SIM]
        skb->priority = 1;
        offset_ns = 0;
        // In the download direction, we usually only limit the receive rate (to prevent flooding).
        // Instead of recalculating specific LinkPolicy bandwidth, use the Pod's uniform SimDownload limit.
        // (You could also look up specific link bandwidth here if needed; usually Upload-side control is more accurate.)
        target_cost = rates->cost_per_byte_sim_download;
    } else {
        // [SYS]
        skb->priority = 0;
        offset_ns = SYS_LATENCY_OFFSET_NS;
        target_cost = rates->cost_per_byte_sys_download; // Limit system traffic!
    }

    // 4. Execute EDT
    __u32 state_key = ifindex * 2 + (is_sim_traffic ? 1 : 0);
    int ret = throttle_flow(skb, target_cost, &edt_download_state_map, state_key, now, horizon_ns);

    // 5. Post-processing (Offset only)
    if (ret == TC_ACT_OK) {
        skb->tstamp += offset_ns;
        // Do not stack physical Latency/Jitter in Download direction to avoid double calculation.
    }

    // 6. Metrics
    if (is_sim_traffic || (bpf_get_prandom_u32() & 0x3F) == 0) {
        update_metrics(ifindex, skb->len, ret, is_sim_traffic, 0); // 0=Download
    }

    return ret;
}

// =============================================================
// Scenario 2: Upload Control (Pod -> Host -> World)
// Hook Point: Pod eth0 -> Egress (Inside Pod Netns)
// Logic: Determine if Dst IP belongs to a Sim node
// =============================================================
SEC("tc/edt_upload")
int handle_edt_upload(struct __sk_buff* skb) {
    __u64 now = bpf_ktime_get_ns();
    __u32 ifindex = skb->ifindex;

    // kuro_debug("handle_edt_upload: ifindex=%u, pkt_len=%u", ifindex, skb->len);

    // 1. Basic Checks
    if (unlikely(ifindex >= MAX_IFINDEX_CAP))
        return TC_ACT_OK;
    struct io_rate* rates = bpf_map_lookup_elem(&rate_map, &ifindex);
    if (!rates)
        return TC_ACT_OK;

    // 2. Parse IP and Ports
    __u32 src_ip = 0;
    __u32 dst_ip = 0;
    // Must obtain both Src and Dst to build a unique link Key
    if (unlikely(!parse_ipv4(skb, &src_ip, &dst_ip)))
        return TC_ACT_OK;

    __u16 src_port = 0;
    __u16 dst_port = 0;
    parse_ports(skb, &src_port, &dst_port);

    // 3. Traffic Classification
    int is_sim_traffic = 0;
    struct link_policy* policy = NULL;

    // A. Port Bypass - Highest priority
    if (is_system_port(src_port) || is_system_port(dst_port)) {
        is_sim_traffic = 0;
    }
    // B. Policy Lookup
    else {
        // Build composite Key: {Who Sent, Who Receives}
        struct policy_key key;
        key.src_ip = src_ip;
        key.dst_ip = dst_ip;

        policy = bpf_map_lookup_elem(&topology_policy_map, &key);

        if (policy) {
            is_sim_traffic = 1;
        } else {
            is_sim_traffic = 0; // Undefined link = System traffic
        }
    }

    // 4. Dual-Lane Configuration
    __u64 target_cost = 0;
    __u64 horizon_ns = 0;
    __u64 offset_ns = 0;

    get_global_config(&horizon_ns);

    if (is_sim_traffic) {
        // kuro_debug("Sim Upload: %pI4:%u -> %pI4:%u", &src_ip, src_port, &dst_ip, dst_port);

        // === [Simulation Lane] ===
        skb->priority = 1; // High Priority
        offset_ns = 0; // Send on time

        if (policy) {
            // kuro_debug("policy found, applying specific link settings");
            // Use specific link policy
            if (policy->cost_per_byte_scaled > 0) {
                // Cost = (10^9 * 8 * 65536) / bw
                target_cost = policy->cost_per_byte_scaled;
            } else {
                target_cost =
                    rates->cost_per_byte_sim_upload; // Default Sim rate if policy unspecified
            }

            if (policy->queue_depth_ns > 0) {
                horizon_ns = policy->queue_depth_ns;
            }

            // Packet Corruption/Loss Simulation (Signal interference)
            if (policy->corruption_threshold > 0) {
                if (bpf_get_prandom_u32() < policy->corruption_threshold)
                    return TC_ACT_SHOT;
            }
        } else {
            // Defensive code: theoretically unreachable as is_sim_traffic=1 implies policy!=NULL
            target_cost = rates->cost_per_byte_sim_upload;
        }
    } else {
        // === [System Lane] ===
        skb->priority = 0; // Low Priority
        offset_ns = SYS_LATENCY_OFFSET_NS; // +3ms Physical avoidance
        target_cost = rates->cost_per_byte_sys_upload; // Bandwidth limit (e.g., 990Mbps)
    }

    // 5. Execute EDT Pacing (The Enforcer)
    // State Key: Sim=Odd, Sys=Even
    __u32 state_key = ifindex * 2 + (is_sim_traffic ? 1 : 0);
    int ret = throttle_flow(skb, target_cost, &edt_upload_state_map, state_key, now, horizon_ns);

    // 6. Post-processing: Physical Simulation & Offsets
    if (ret == TC_ACT_OK) {
        // Apply offset for system traffic
        skb->tstamp += offset_ns;

        // Apply physical delay for simulation traffic (Sim only)
        if (is_sim_traffic && policy) {
            skb->tstamp += policy->base_latency_ns;

            if (policy->jitter_ns > 0) {
                // Simple jitter simulation: + Random(0, Jitter)
                skb->tstamp += (bpf_get_prandom_u32() % policy->jitter_ns);
            }
        }
    }

    // 7. Statistics & Metrics
    if (is_sim_traffic || (bpf_get_prandom_u32() & 0x3F) == 0) {
        update_metrics(ifindex, skb->len, ret, is_sim_traffic, 1); // 1=Upload
    }

    // Latency Histogram (Record successful Sim traffic only)
    if (is_sim_traffic && ret == TC_ACT_OK && (bpf_get_prandom_u32() & 0x7F) == 0) {
        __u64 latency = (skb->tstamp > now) ? (skb->tstamp - now) : 0;
        update_latency_hist(ifindex, latency);
    }

    return ret;
}

// =============================================================
// Scenario 3: Global Egress Control (Host Physical NIC)
// Hook: Host Eth0 Egress
// Logic: Catch Host-local traffic and enforce global scheduling
// =============================================================
SEC("tc/eth0_egress")
int handle_eth0_egress(struct __sk_buff* skb) {
    // 1. Check Priority
    // Priority 1 = Set by Veth (Sim Traffic). It already has a correct tstamp.
    if (skb->priority == 1) {
        return TC_ACT_OK;
    }

    // 2. Handle Sys Traffic (Priority 0)
    // This includes:
    // a) Traffic from Pods marked as Sys (already has tstamp set by Veth)
    // b) Traffic from Host processes (tstamp is 0)

    // If tstamp is 0, it means it's Host-local traffic (SSH, Kubelet, etc.)
    // We must delay it to prevent it from jumping ahead of Sim traffic.
    if (skb->tstamp == 0) {
        __u64 now = bpf_ktime_get_ns();
        skb->tstamp = now + SYS_LATENCY_OFFSET_NS;
    }

    // If tstamp was already set by Veth, we respect it (do nothing).

    return TC_ACT_OK;
}

// =============================================================
// Scenario 4: Ingress Protection (Host Physical NIC)
// Hook: Host Eth0 Ingress (XDP)
// Logic: Allow Sim traffic unconditionally; Rate limit Sys traffic.
// =============================================================
SEC("xdp")
int handle_xdp_ingress(struct xdp_md* ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    // 1. Parse Ethernet Header
    struct ethhdr* eth = data;
    if ((void*)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // Pass non-IP packets
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // 2. Parse IPv4 Header
    struct iphdr* iph = (void*)(eth + 1);
    if ((void*)(iph + 1) > data_end) {
        return XDP_DROP;
    }

    // ============================================================
    // NEW: Port Parsing and System Traffic Identification (Port Bypass Logic)
    // ============================================================
    int is_sys_traffic = 0;
    __u16 src_port = 0;
    __u16 dst_port = 0;

    int ip_hlen = iph->ihl * 4;
    void* trans = (void*)iph + ip_hlen; // Transport layer header position

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr* tcph = trans;
        if ((void*)(tcph + 1) <= data_end) {
            src_port = bpf_ntohs(tcph->source);
            dst_port = bpf_ntohs(tcph->dest);
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr* udph = trans;
        if ((void*)(udph + 1) <= data_end) {
            src_port = bpf_ntohs(udph->source);
            dst_port = bpf_ntohs(udph->dest);
        }
    }

    // If matches SSH/K8s/Monitoring ports, force into rate-limiting channel (System Traffic)
    if (is_system_port(src_port) || is_system_port(dst_port)) {
        is_sys_traffic = 1;
    }

    int is_sim = 0;

    // Only check for simulation traffic if it's not a management port
    if (!is_sys_traffic) {
        struct policy_key key;
        key.src_ip = iph->saddr; // Network Byte Order
        key.dst_ip = iph->daddr; // Network Byte Order

        // Lookup: Does a defined simulation link exist between this IP pair?
        // NOTE: XDP executes at the physical NIC ingress. Dst IP could be Host IP or Pod IP (depending on network mode).
        // If a policy is matched, treat as simulation traffic.
        if (bpf_map_lookup_elem(&topology_policy_map, &key)) {
            is_sim = 1;
        }
    }

    if (is_sim) {
        return XDP_PASS;
    }

    __u32 key = 0;
    struct ingress_config* cfg = bpf_map_lookup_elem(&ingress_config_map, &key);
    struct ingress_state* st = bpf_map_lookup_elem(&ingress_state_map, &key);

    if (!cfg || !st)
        return XDP_PASS;
    if (cfg->cost_per_byte_ns_scaled == 0)
        return XDP_PASS;

    __u64 now = bpf_ktime_get_ns();
    __u64 pkt_len = (__u64)(data_end - data);
    int action = XDP_PASS;

    bpf_spin_lock(&st->lock);

    if (unlikely(st->last_updated == 0)) {
        st->last_updated = now;
        st->tokens_ns = cfg->burst_ns;
    }

    __u64 delta_ns = now - st->last_updated;
    if (delta_ns > NSEC_PER_SEC)
        delta_ns = NSEC_PER_SEC;

    st->tokens_ns += delta_ns;
    if (st->tokens_ns > cfg->burst_ns)
        st->tokens_ns = cfg->burst_ns;

    __u64 packet_cost_ns = (pkt_len * cfg->cost_per_byte_ns_scaled) >> 16;

    if (st->tokens_ns >= packet_cost_ns) {
        st->tokens_ns -= packet_cost_ns;
        action = XDP_PASS;
    } else {
        action = XDP_DROP;
    }

    st->last_updated = now;
    bpf_spin_unlock(&st->lock);

    return action;
}

char __license[] SEC("license") = "GPL";
