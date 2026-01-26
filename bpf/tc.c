#include "include/helper.h"
#include "include/map.h"

// =============================================================
// Constant Definitions
// =============================================================

// TODO: there constant variables should be configurable

// Burst Allowance: 5ms
// Allows simulation traffic a small burst after an idle period (e.g., TCP handshake or ACKs).
// This avoids excessively high initial latency caused by strict pacing.
#define BURST_WINDOW_NS (5ULL * 1000000ULL)

// Sys Traffic Latency Offset: 3ms
// Artificial delay added to "System" (business) traffic.
// Purpose: In the FQ (Fair Queueing) scheduler of the host physical NIC,
// the timestamp for Sys traffic will always be 3ms later than Sim traffic.
// Result: As long as Sim traffic isn't severely backlogged, it will always be prioritized.
#define SYS_LATENCY_OFFSET_NS (3ULL * 1000000ULL)

// Ethernet Header Length
#define ETH_HLEN 14

// =============================================================
// Helper Functions
// =============================================================

/**
 * EDT (Earliest Departure Time) Rate Limiting Core Logic (Used for Sim traffic)
 * @param rate: Limit rate (bps)
 * @param state_map: Pointer to the state Map
 * @param target_idx: Map Key (ifindex)
 */
static __always_inline int
throttle_flow(struct __sk_buff* skb, __u64 rate, void* state_map, __u32 target_idx, __u64 now) {
    // 1. Rate check
    if (rate == 0) {
        // Rate set to 0 while limiting is active is treated as a block
        return TC_ACT_SHOT;
    }

    // 2. Retrieve state
    struct edt_state* st = bpf_map_lookup_elem(state_map, &target_idx);
    if (!st) {
        return TC_ACT_OK; // No state found, pass through by default
    }

    // 3. Get global configuration (Maximum delay horizon)
    __u64 horizon_ns;
    get_global_config(&horizon_ns);

    __u64 packet_len = skb->len;

    // Calculate physical time required to send this packet: Time = (Bytes * 8 * 10^9) / Rate_bps
    __u64 packet_time_ns = (packet_len * 8 * NSEC_PER_SEC) / rate;

    __u64 t_send;

    // 4. Critical Section: Calculate EDT timestamp
    bpf_spin_lock(&st->lock);

    __u64 t_last = st->t_last;
    __u64 t_start = t_last;

    // Handle Burst Window: If link has been idle for a long time, reset t_start to (now - burst)
    __u64 burst_start = 0;
    if (now > BURST_WINDOW_NS) [[clang::likely]] {
        burst_start = now - BURST_WINDOW_NS;
    }

    if (t_start < burst_start) {
        t_start = burst_start;
    }

    t_send = t_start + packet_time_ns;

    // Queue Depth Protection: If departure time is pushed too far into the future,
    // drop the packet to prevent Buffer Bloat.
    if (t_send > now + horizon_ns) [[clang::unlikely]] {
        bpf_spin_unlock(&st->lock);
        // kuro_debug("EDT Drop: ifindex %d, Queue too deep\n", target_idx);
        return TC_ACT_SHOT;
    }

    st->t_last = t_send;
    bpf_spin_unlock(&st->lock);

    // 5. Set skb->tstamp for FQ scheduling
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
    __u32 ifindex = skb->ifindex;

    // 1. Look up rate limit configuration (pass if none configured)
    struct io_rate* rates = bpf_map_lookup_elem(&rate_map, &ifindex);
    if (!rates) {
        return TC_ACT_OK;
    }

    // 2. Parse packet to get Source IP
    __u32 src_ip = 0;
    if (!parse_ipv4(skb, &src_ip, NULL)) [[clang::unlikely]] {
        // Non-IPv4 (ARP/IPv6) is ignored and passed as-is (Priority 0, tstamp 0)
        return TC_ACT_OK;
    }

    // 3. Check Whitelist: Is the Source IP a simulation peer?
    __u8* is_sim = bpf_map_lookup_elem(&simulation_peers_map, &src_ip);
    __u64 now = bpf_ktime_get_ns();

    if (is_sim) {
        // [SIM Traffic Branch]
        // Mark as high priority and perform precise rate limiting
        skb->priority = 1;
        return throttle_flow(skb, rates->rate_download, &edt_download_state_map, ifindex, now);
    }

    skb->tstamp = now + SYS_LATENCY_OFFSET_NS;
    skb->priority = 0;

    return TC_ACT_OK;
}

// =============================================================
// Scenario 2: Upload Control (Pod -> Host -> World)
// Hook Point: Pod eth0 -> Egress (Inside Pod Netns)
// Logic: Determine if Dst IP belongs to a Sim node
// =============================================================
SEC("tc/edt_upload")
int handle_edt_upload(struct __sk_buff* skb) {
    __u32 ifindex = skb->ifindex;

    // 1. Look up rate limit configuration
    struct io_rate* rates = bpf_map_lookup_elem(&rate_map, &ifindex);
    if (!rates) {
        return TC_ACT_OK;
    }

    // 2. Parse packet to get Destination IP
    __u32 dst_ip = 0;
    if (!parse_ipv4(skb, NULL, &dst_ip)) [[clang::unlikely]] {
        return TC_ACT_OK;
    }

    // 3. Check Whitelist: Is the Destination IP a simulation peer?
    __u8* is_sim = bpf_map_lookup_elem(&simulation_peers_map, &dst_ip);
    __u64 now = bpf_ktime_get_ns();

    if (is_sim) {
        // [SIM Traffic Branch]
        skb->priority = 1;
        return throttle_flow(skb, rates->rate_upload, &edt_upload_state_map, ifindex, now);
    }

    skb->tstamp = now + SYS_LATENCY_OFFSET_NS;
    skb->priority = 0;

    return TC_ACT_OK;
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

char __license[] SEC("license") = "GPL";
