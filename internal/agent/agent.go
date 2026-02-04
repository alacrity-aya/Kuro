// Package agent
package agent

import (
	"context"
	"fmt"
	"log"
	"time"

	"kuro/internal/agent/bpf"
	"kuro/internal/agent/opsapi"
	"kuro/internal/agent/remote"
	"kuro/internal/agent/watch"

	"k8s.io/client-go/kubernetes"
)

const hostInterface = "eth0"

type Agent struct {
	localWatcher *watch.LocalWatcher // Local Pod Watcher (for Netns management)
	bpfManager   *bpf.BpfManager
	grpcClient   *remote.Client
	httpService  *opsapi.HTTPService // Added HTTP service component

	nodeName string
	errCh    chan error
}

func NewAgent(socketpath string, clientSet kubernetes.Interface, nodeName string, targetNs string, controllerAddr string) (*Agent, error) {
	containerRuntime, err := watch.NewContainerRuntime(socketpath)
	if err != nil {
		return nil, err
	}

	manager, err := bpf.NewBpfManager()
	if err != nil {
		return nil, err
	}

	localWatcher := watch.NewLocalWatcher(clientSet, containerRuntime, nodeName, targetNs)
	httpSvc := opsapi.NewHTTPService(localWatcher, manager)

	a := &Agent{
		localWatcher: localWatcher,
		bpfManager:   manager,
		httpService:  httpSvc,
		nodeName:     nodeName,
		errCh:        make(chan error, 1),
	}

	// 'a' implements AgentHandler interface (using domain objects now)
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
			// Send to gRPC transmission queue
			a.grpcClient.EnqueueEvent(event)
		}
	}
}

func (a *Agent) Run(ctx context.Context) error {
	// 1. Start HTTP Service
	go func() {
		// Port is hardcoded to 8080; could be moved to configuration
		a.httpService.Start(8080)
	}()

	// 2. Start gRPC Client
	go func() {
		log.Println("[Agent] Starting Remote Client...")
		if err := a.grpcClient.Start(ctx); err != nil {
			log.Printf("[Agent] Remote Client stopped: %v", err)
		}
	}()

	// 3. Initialize BPF default rules
	if err := a.bpfManager.AttachIngressProtection(hostInterface, 0, 64*1024); err != nil {
		log.Printf("[Agent] Warning: Failed to attach initial ingress protection: %v", err)
	}
	if err := a.bpfManager.AttachNICEgress(hostInterface); err != nil {
		log.Printf("[Agent] Warning: Failed to attach initial egress hook: %v", err)
	}

	// 4. Start Local Watcher
	go func() {
		log.Println("[Agent] Starting Local Watcher...")
		if err := a.localWatcher.Start(ctx); err != nil {
			a.errCh <- fmt.Errorf("local watcher crashed: %w", err)
		}
	}()

	// 5. Start event forwarding
	go a.watchLocalEvents(ctx)

	ticker := time.NewTicker(60 * time.Second)
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
