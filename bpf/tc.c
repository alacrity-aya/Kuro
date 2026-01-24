#include "include/helper.h"
#include "include/map.h"

// Burst Allowance: 5ms
// Allows a small burst of packets to pass immediately when the link is idle.
// For 10Mbps, 5ms ~ 6.25KB, sufficient for TCP Handshake + Initial Window.
#define BURST_WINDOW_NS (5ULL * 1000000ULL)

/**
 * Generic EDT Rate Limiting Logic
 * @param rate: Rate limit in bits per second (bps)
 * @param state_map: Corresponding state Map (passed separately to support full-duplex)
 * @param target_idx: Key used to look up state in state_map (usually the veth ifindex)
 */
static __always_inline int
throttle_flow(struct __sk_buff* skb, __u64 rate, void* state_map, __u32 target_idx) {
    // 1. Rate Check
    if (rate == 0) {
        // If an entry is configured but rate is 0, treat as a block (drop packet)
        return TC_ACT_SHOT;
    }

    // 2. Retrieve State
    struct edt_state* st = bpf_map_lookup_elem(state_map, &target_idx);
    if (!st) {
        // If state is not initialized, allow by default
        return TC_ACT_OK;
    }

    // 3. Retrieve configuration and time
    __u64 horizon_ns;
    get_global_config(&horizon_ns);

    __u64 now = bpf_ktime_get_ns();
    __u64 packet_len = skb->len;

    // Calculation: Time = (Bytes * 8 * 10^9) / Rate_bps
    // Precision fix: Multiply first
    __u64 packet_time_ns = (packet_len * 8 * NSEC_PER_SEC) / rate;

    __u64 t_send;

    // 4. Critical Section: Calculate transmission time
    bpf_spin_lock(&st->lock);

    __u64 t_last = st->t_last;
    __u64 t_start = t_last;

    __u64 burst_start = 0;
    if (now > BURST_WINDOW_NS) {
        burst_start = now - BURST_WINDOW_NS;
    }

    if (t_start < burst_start) {
        t_start = burst_start;
    }

    t_send = t_start + packet_time_ns;

    // Check if it exceeds the maximum delay limit (prevents the queue from growing too deep)
    if (t_send > now + horizon_ns) {
        bpf_spin_unlock(&st->lock);
        // kuro_debug("EDT Drop: ifindex %d, Queue too deep", target_idx);
        return TC_ACT_SHOT;
    }

    st->t_last = t_send;
    bpf_spin_unlock(&st->lock);

    // 5. Set timestamp, let FQ Qdisc handle the scheduling
    skb->tstamp = t_send;

    return TC_ACT_OK;
}

// =============================================================
// Scenario 1: Download Control (Host -> Pod)
// Attachment Point: Host Veth Interface -> Egress
// Logic: Here skb->ifindex is the veth; we lookup the download rate for this ID.
// =============================================================
SEC("tc/edt_download")
int handle_edt_download(struct __sk_buff* skb) {
    __u32 ifindex = skb->ifindex;

    // Lookup rate configuration
    struct io_rate* rates = bpf_map_lookup_elem(&rate_map, &ifindex);
    if (!rates) {
        return TC_ACT_OK; // No configuration, no rate limiting
    }

    // Invoke generic logic for Download
    return throttle_flow(skb, rates->rate_download, &edt_download_state_map, ifindex);
}

// =============================================================
// Scenario 2: Upload Control (Pod -> Host -> World)
// Attachment Point: Pod eth0 -> Egress (Inside Pod Netns)
// Logic:
//   Packet is leaving the Pod. Since we are attached inside the Pod Netns,
//   skb->ifindex is directly the index of eth0.
// =============================================================
SEC("tc/edt_upload")
int handle_edt_upload(struct __sk_buff* skb) {
    // Key: use current interface index (eth0)
    // Manager.go has correctly stored the eth0 index as the Key in the Map
    __u32 ifindex = skb->ifindex;

    struct io_rate* rates = bpf_map_lookup_elem(&rate_map, &ifindex);
    if (!rates) {
        return TC_ACT_OK;
    }

    // Invoke generic logic for Upload
    return throttle_flow(skb, rates->rate_upload, &edt_upload_state_map, ifindex);
}

char __license[] SEC("license") = "GPL";
