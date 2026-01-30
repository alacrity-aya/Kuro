// Package agent
package agent

import (
	"context"
	"fmt"
	"log"
	"time"

	pb "kuro/api/v1"

	"kuro/internal/agent/bpf"
	"kuro/internal/agent/remote"
	"kuro/internal/agent/watch"

	"k8s.io/client-go/kubernetes"
)

const hostInterface = "eth0"

type Agent struct {
	localWatcher *watch.LocalWatcher // Local Pod Watcher (for Netns management)
	bpfManager   *bpf.BpfManager
	grpcClient   *remote.Client

	nodeName string
	errCh    chan error
}

func NewAgent(socketpath string, clientSet kubernetes.Interface, nodeName string, targetNs string, controllerAddr string) (*Agent, error) {
	// 1. Initialize Container Runtime Client
	containerRuntime, err := watch.NewContainerRuntime(socketpath)
	if err != nil {
		return nil, err
	}

	// 2. Initialize BPF Manager
	manager, err := bpf.NewBpfManager()
	if err != nil {
		return nil, err
	}

	// 3. Initialize Local Watcher (Monitors current node only)
	localWatcher := watch.NewLocalWatcher(clientSet, containerRuntime, nodeName, targetNs)

	// PeerWatcher has been removed

	a := &Agent{
		localWatcher: localWatcher,
		bpfManager:   manager,
		nodeName:     nodeName,
		errCh:        make(chan error, 1),
	}

	// 4. Initialize gRPC Client
	// Note: 'a' is passed here because Agent implements the AgentHandler interface
	// nodeIP := "127.0.0.1" // In production, this should be the host's real IP retrieved dynamically
	grpcClient, err := remote.NewClient(controllerAddr, nodeName, a)
	if err != nil {
		return nil, fmt.Errorf("failed to init grpc client: %w", err)
	}
	a.grpcClient = grpcClient

	return a, nil
}

func (a *Agent) watchLocalEvents(ctx context.Context) {
	log.Println("[Agent] Event loop started: Forwarding LocalWatcher -> gRPC Client")

	eventCh := a.localWatcher.GetEventCh()

	for {
		select {
		case <-ctx.Done():
			return
		case event := <-eventCh:
			// to grpc send queue
			if event != nil {
				a.grpcClient.EnqueueEvent(event)
			}
		}
	}
}

func (a *Agent) Run(ctx context.Context) error {
	go a.startHTTPServer()

	go func() {
		log.Println("[Agent] Starting Remote Client...")
		// Start gRPC bidirectional stream (heartbeats, event reporting, command receiving)
		if err := a.grpcClient.Start(ctx); err != nil {
			log.Printf("[Agent] Remote Client stopped: %v", err)
		}
	}()

	// Enable node-level protection by default
	// Note: Parameters 0 indicates default rate, 64KB burst
	if err := a.bpfManager.AttachIngressProtection(hostInterface, 0, 64*1024); err != nil {
		log.Printf("[Agent] Warning: Failed to attach initial ingress protection: %v", err)
	}
	if err := a.bpfManager.AttachNICEgress(hostInterface); err != nil {
		log.Printf("[Agent] Warning: Failed to attach initial egress hook: %v", err)
	}

	// Start Local Watcher goroutine
	go func() {
		log.Println("[Agent] Starting Local Watcher...")
		if err := a.localWatcher.Start(ctx); err != nil {
			a.errCh <- fmt.Errorf("local watcher crashed: %w", err)
		}
	}()

	// Monitor Local Watcher events and forward them to the gRPC Client
	// This decouples the Watcher from the gRPC logic
	go a.watchLocalEvents(ctx)

	// PeerWatcher startup logic removed

	ticker := time.NewTicker(30 * time.Second) // Reduced frequency for debug logs
	defer ticker.Stop()

	log.Println("[Agent] Running main loop...")

	for {
		select {
		case <-ctx.Done():
			log.Println("[Agent] Context cancelled, shutting down...")
			a.localWatcher.Stop()
			a.grpcClient.Stop()
			a.bpfManager.Close()
			return nil

		case err := <-a.errCh:
			log.Printf("[Agent] Fatal Error: %v\n", err)
			return err

		case <-ticker.C:
			a.printDebugStats()
		}
	}
}

func (a *Agent) printDebugStats() {
	truncate := func(s string, n int) string {
		if len(s) > n {
			return s[:n]
		}
		return s
	}

	pods := a.localWatcher.GetAllPods()
	log.Printf("--- [Debug Audit] Current Memory State ---")
	log.Printf("Total Tracked Pods: %d", len(pods))
	for _, p := range pods {
		status := "Closed"
		if p.NetnsHandle.IsOpen() {
			status = "Active"
		}
		log.Printf("  - Pod: %-15s | Veth: %-15s | Handle: %s",
			p.Info.Name,

			truncate(p.Info.HostVeth, 15),
			status,
		)
	}
	log.Printf("------------------------------------------")
}

// =============================================================
// Implementation of the remote.AgentHandler Interface
// =============================================================

// GetAgentStatus constructs the heartbeat packet
func (a *Agent) GetAgentStatus() *pb.Heartbeat {
	pods := a.localWatcher.GetAllPods()
	// TODO: Retrieve the actual Node IP
	return &pb.Heartbeat{
		NodeName:        a.nodeName,
		NodeIp:          "127.0.0.1",
		ManagedPodCount: int32(len(pods)),
	}
}

// ApplyPolicy handles Pod-level rate limiting policies
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
	// Check for nil to prevent panics
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

// ApplyNodePolicy handles node interface policies (Ingress Protection)
func (a *Agent) ApplyNodePolicy(cmd *pb.ApplyNodePolicy) error {
	log.Printf("[Agent] Applying Node Policy: Limit=%d bps, Burst=%d bytes", cmd.IngressLimitBps, cmd.IngressBurstBytes)
	return a.bpfManager.AttachIngressProtection(hostInterface, cmd.IngressLimitBps, cmd.IngressBurstBytes)
}

// SyncWhitelist handles global whitelist synchronization
func (a *Agent) SyncWhitelist(cmd *pb.SyncPeerWhitelist) error {
	if cmd == nil {
		return nil
	}

	// Delegate the diff logic completely to BpfManager
	if err := a.bpfManager.SyncPeers(cmd.PeerIps); err != nil {
		return fmt.Errorf("failed to sync peers to bpf map: %w", err)
	}

	return nil
}
