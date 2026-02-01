package agent

import (
	"fmt"
	"log"

	"kuro/internal/agent/bpf"
	"kuro/internal/domain"
)

// =============================================================
// Implementation of the remote.AgentHandler Interface
// =============================================================

// GetAgentStatus constructs a domain heartbeat.
func (a *Agent) GetAgentStatus() domain.Heartbeat {
	pods := a.localWatcher.GetAllPods()
	return domain.Heartbeat{
		NodeName:        a.nodeName,
		NodeIP:          "127.0.0.1", // In production use real IP
		ManagedPodCount: len(pods),
		// Timestamp is handled by the transport layer (remote/client.go) usually,
		// or here if business logic dictates it.
	}
}

// ApplyPolicy handles Pod-level interface rate limits (Default Sim/Sys rates).
func (a *Agent) ApplyPolicy(policy domain.PodPolicy) error {
	podName := policy.PodName

	// 1. Retrieve Pod Context
	podCtx, ok := a.localWatcher.GetPodContext(podName)
	if !ok {
		return fmt.Errorf("pod %s not found in local cache", podName)
	}

	if !podCtx.NetnsHandle.IsOpen() {
		return fmt.Errorf("netns for %s is closed", podName)
	}

	// 2. Ensure BPF program is attached
	if err := a.bpfManager.AddPod(podName, podCtx.Info.HostIfIndex, podCtx.NetnsHandle); err != nil {
		return fmt.Errorf("attach bpf failed: %w", err)
	}

	// 3. Update Rate Map
	var simUp, simDown, sysUp, sysDown uint64
	if policy.SimRate != nil {
		simUp = policy.SimRate.UploadBps
		simDown = policy.SimRate.DownloadBps
	}
	if policy.SysRate != nil {
		sysUp = policy.SysRate.UploadBps
		sysDown = policy.SysRate.DownloadBps
	}

	return a.bpfManager.UpdateRule(podCtx.Info.HostIfIndex, simUp, simDown, sysUp, sysDown)
}

// ApplyLinkPolicy handles specific point-to-point link physics.
func (a *Agent) ApplyLinkPolicy(policy domain.LinkPolicy) error {
	if policy.SrcIP == "" || policy.DstIP == "" {
		return fmt.Errorf("invalid link policy: missing src or dst ip")
	}

	var tcPolicy *bpf.TcLinkPolicy

	// Check the IsDelete flag we added to the Domain model
	if !policy.IsDelete {
		tcPolicy = &bpf.TcLinkPolicy{
			BandwidthLimit:    policy.BandwidthBps,
			BaseLatencyNs:     policy.BaseLatencyNs,
			JitterNs:          policy.JitterNs,
			CorruptionRatePpm: policy.CorruptionRatePpm,
			QueueDepthNs:      policy.QueueDepthNs,
		}
	}

	log.Printf("[Agent] Applying Link Policy: %s -> %s (Delete=%v)",
		policy.SrcIP, policy.DstIP, policy.IsDelete)

	return a.bpfManager.SetPolicy(policy.SrcIP, policy.DstIP, tcPolicy)
}

// ApplyNodePolicy handles node-level XDP ingress protection.
func (a *Agent) ApplyNodePolicy(policy domain.NodePolicy) error {
	log.Printf("[Agent] Applying Node Policy: Limit=%d bps, Burst=%d bytes",
		policy.IngressLimitBps, policy.IngressBurstBytes)

	// Assuming hostInterface is available in Agent struct or global config
	// You might need to pass it when initializing Agent
	hostIf := "eth0" // Replace with a.hostInterface
	return a.bpfManager.AttachIngressProtection(hostIf, policy.IngressLimitBps, policy.IngressBurstBytes)
}
