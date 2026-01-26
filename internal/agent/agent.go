// Package agent
package agent

import (
	"context"
	"fmt"
	"log"
	"time"

	"kuro/internal/agent/bpf"
	"kuro/internal/agent/watch"

	"k8s.io/client-go/kubernetes"
)

const hostInterface = "eth0"

type Agent struct {
	localWatcher *watch.LocalWatcher // Local Pod Watcher (for Netns)
	peerWatcher  *watch.PeerWatcher  // Global Pod Watcher (for IP Whitelist)
	bpfManager   *bpf.BpfManager

	errCh chan error
}

func NewAgent(socketpath string, clientSet kubernetes.Interface, nodeName string, targetNs string) (*Agent, error) {
	containerRuntime, err := watch.NewContainerRuntime(socketpath)
	if err != nil {
		return nil, err
	}
	manager, err := bpf.NewBpfManager()
	if err != nil {
		return nil, err
	}
	localWatcher := watch.NewLocolWatcher(clientSet, containerRuntime, nodeName, targetNs)
	peerWatcher := watch.NewPeerWatcher(clientSet, manager, targetNs)

	return &Agent{
		localWatcher: localWatcher,
		peerWatcher:  peerWatcher,
		bpfManager:   manager,
		errCh:        make(chan error, 1),
	}, nil
}

func (a *Agent) Run(ctx context.Context) error {
	go a.startDebugServer()

	go func() {
		log.Println("[Agent] Starting Local Watcher...")
		if err := a.localWatcher.Start(ctx); err != nil {
			a.errCh <- fmt.Errorf("local watcher crashed: %w", err)
		}
	}()

	go func() {
		log.Println("[Agent] Starting Peer Watcher...")
		if err := a.peerWatcher.Start(ctx); err != nil {
			a.errCh <- fmt.Errorf("peer watcher crashed: %w", err)
		}
	}()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	log.Println("[Agent] Running main loop...")

	for {
		select {
		case <-ctx.Done():
			log.Println("[Agent] Context cancelled, shutting down...")
			a.localWatcher.Stop()
			a.peerWatcher.Stop()
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

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
