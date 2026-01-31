package agent

import (
	"fmt"
	"log"

	pb "kuro/api/v1"
)

// =============================================================
// Implementation of the remote.AgentHandler Interface
// This file is specifically for handling callbacks or commands
// sent from the Controller via gRPC.
// =============================================================

// GetAgentStatus constructs a heartbeat packet.
// Corresponds to the AgentStatus retrieval logic required by remote.Client.
func (a *Agent) GetAgentStatus() *pb.Heartbeat {
	pods := a.localWatcher.GetAllPods()
	// TODO: Retrieve the actual Node IP if needed
	return &pb.Heartbeat{
		NodeName:        a.nodeName,
		NodeIp:          "127.0.0.1",
		ManagedPodCount: int32(len(pods)),
	}
}

// ApplyPolicy handles the delivery of Pod-level traffic control policies.
func (a *Agent) ApplyPolicy(cmd *pb.ApplyPodPolicy) error {
	podName := cmd.PodName

	// 1. Retrieve Pod Context (Netns)
	podCtx, ok := a.localWatcher.GetPodContext(podName)
	if !ok {
		return fmt.Errorf("pod %s not found in local cache", podName)
	}

	if !podCtx.NetnsHandle.IsOpen() {
		return fmt.Errorf("netns for %s is closed", podName)
	}

	// 2. Ensure BPF program is attached (idempotent operation)
	if err := a.bpfManager.AddPod(podName, podCtx.Info.HostIfIndex, podCtx.NetnsHandle); err != nil {
		return fmt.Errorf("attach bpf failed: %w", err)
	}

	// 3. Update rules in BPF Map
	var simUp, simDown, sysUp, sysDown uint64
	if cmd.SimRate != nil {
		simUp = cmd.SimRate.UploadBps
		simDown = cmd.SimRate.DownloadBps
	}
	if cmd.SysRate != nil {
		sysUp = cmd.SysRate.UploadBps
		sysDown = cmd.SysRate.DownloadBps
	}

	return a.bpfManager.UpdateRule(podCtx.Info.HostIfIndex, simUp, simDown, sysUp, sysDown)
}

// ApplyNodePolicy handles node-level network interface policies (Ingress Protection).
func (a *Agent) ApplyNodePolicy(cmd *pb.ApplyNodePolicy) error {
	log.Printf("[Agent] Applying Node Policy: Limit=%d bps, Burst=%d bytes", cmd.IngressLimitBps, cmd.IngressBurstBytes)
	return a.bpfManager.AttachIngressProtection(hostInterface, cmd.IngressLimitBps, cmd.IngressBurstBytes)
}

// SyncWhitelist handles global peer whitelist synchronization.
func (a *Agent) SyncWhitelist(cmd *pb.SyncPeerWhitelist) error {
	if cmd == nil {
		return nil
	}

	// Delegate the Diff logic entirely to the BpfManager
	if err := a.bpfManager.SyncPeers(cmd.PeerIps); err != nil {
		return fmt.Errorf("failed to sync peers to bpf map: %w", err)
	}

	return nil
}
