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
	// Log only if you need high-frequency debugging, otherwise this might be too noisy.
	// log.Println("[Agent] GetAgentStatus called")

	pods := a.localWatcher.GetAllPods()

	// Useful to know if the agent actually sees the pods
	if len(pods) > 0 {
		log.Printf("[Agent] Status Check: Managing %d pods", len(pods))
	}

	return domain.Heartbeat{
		NodeName:        a.nodeName,
		NodeIP:          "127.0.0.1", // In production use real IP
		ManagedPodCount: len(pods),
		// Timestamp is handled by the transport layer (remote/client.go) usually,
		// or here if business logic dictates it.
	}
}

func (a *Agent) ensurePodInfraReadyByIP(ip string) error {
	podName, found := a.localWatcher.LookupPodByIP(ip)
	if !found {
		return nil
	}

	podCtx, ok := a.localWatcher.GetPodContext(podName)
	if !ok {
		return fmt.Errorf("pod context missing for name %s", podName)
	}

	if !podCtx.NetnsHandle.IsOpen() {
		return fmt.Errorf("netns closed for %s", podName)
	}

	if err := a.bpfManager.EnsurePodAttached(podName, podCtx.Info.IP, podCtx.Info.HostIfIndex, podCtx.NetnsHandle); err != nil {
		return fmt.Errorf("ensure pod attached: %w", err)
	}

	return nil
}

// ApplyPolicy handles Pod-level interface rate limits.
func (a *Agent) ApplyPolicy(policy domain.PodPolicy) error {
	podName := policy.PodName
	// 1. Retrieve Pod Context
	podCtx, ok := a.localWatcher.GetPodContext(podName)
	if !ok || !podCtx.NetnsHandle.IsOpen() {
		return fmt.Errorf("pod %s not found or netns closed", podName)
	}

	if err := a.bpfManager.EnsurePodAttached(podName, podCtx.Info.IP, podCtx.Info.HostIfIndex, podCtx.NetnsHandle); err != nil {
		return fmt.Errorf("attach infra failed: %w", err)
	}

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
	if policy.SrcIP != "" {
		if err := a.ensurePodInfraReadyByIP(policy.SrcIP); err != nil {
			log.Printf("[Agent] WARNING: Failed to ensure infra for SrcIP %s: %v", policy.SrcIP, err)
		}
	}

	var tcPolicy *bpf.NetworkPolicyConfig
	if !policy.IsDelete {
		tcPolicy = &bpf.NetworkPolicyConfig{
			BandwidthLimit:    policy.BandwidthBps,
			QueueDepthNs:      policy.QueueDepthNs,
			BaseLatencyNs:     policy.BaseLatencyNs,
			JitterNs:          policy.JitterNs,
			CorruptionRatePpm: policy.CorruptionRatePpm,
		}
	}

	return a.bpfManager.SetPolicy(policy.SrcIP, policy.DstIP, tcPolicy)
}

// ApplyNodePolicy handles node-level XDP ingress protection.
func (a *Agent) ApplyNodePolicy(policy domain.NodePolicy) error {
	log.Printf("[Agent] ApplyNodePolicy Request: Limit=%d bps, Burst=%d bytes",
		policy.IngressLimitBps, policy.IngressBurstBytes)

	// Assuming hostInterface is available in Agent struct or global config
	// You might need to pass it when initializing Agent
	hostIf := "eth0" // Replace with a.hostInterface if available

	log.Printf("[Agent] Attaching Ingress Protection to interface: %s", hostIf)

	err := a.bpfManager.AttachIngressProtection(hostIf, policy.IngressLimitBps, policy.IngressBurstBytes)
	if err != nil {
		log.Printf("[Agent] ERROR: AttachIngressProtection failed: %v", err)
		return err
	}

	log.Println("[Agent] Node Policy applied successfully")
	return nil
}
