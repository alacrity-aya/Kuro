// Package agent
package agent

import (
	"context"
	"fmt"
	"log"
	"time"

	"kuro/internal/agent/netns"

	"k8s.io/client-go/kubernetes"
)

type Agent struct {
	watcher *netns.Watcher

	errCh chan error
}

func NewAgent(socketpath string, clientSet kubernetes.Interface, nodeName string, targetNs string) (*Agent, error) {
	containerRuntime, err := netns.NewContainerRuntime(socketpath)
	if err != nil {
		return nil, err
	}
	watcher := netns.NewWatcher(clientSet, containerRuntime, nodeName, targetNs)
	return &Agent{watcher: watcher, errCh: make(chan error, 1)}, nil
}

func (a *Agent) Run(ctx context.Context) error {
	go func() {
		log.Println("[Agent] Starting Watcher...")
		if err := a.watcher.Start(ctx); err != nil {
			a.errCh <- fmt.Errorf("watcher crashed: %w", err)
		}
	}()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	log.Println("[Agent] Running main loop...")

	for {
		select {
		case <-ctx.Done():
			log.Println("[Agent] Context cancelled, shutting down...")
			a.watcher.Stop() // 优雅关闭，清理 Netns Handles
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
	pods := a.watcher.GetAllPods()
	log.Printf("--- [Debug Audit] Current Memory State ---")
	log.Printf("Total Tracked Pods: %d", len(pods))
	for _, p := range pods {
		status := "Closed"
		if p.NetnsHandle.IsOpen() {
			status = "Open/Active"
		}
		log.Printf("  - Pod: %-15s | ContainerID: %-12s... | Handle: %s",
			p.Info.Name,
			truncate(p.Info.ContainerID, 12),
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
