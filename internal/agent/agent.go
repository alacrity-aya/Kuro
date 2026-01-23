// Package agent
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"kuro/internal/agent/bpf"
	"kuro/internal/agent/netns"

	"k8s.io/client-go/kubernetes"
)

type Agent struct {
	watcher    *netns.Watcher
	bpfManager *bpf.BpfManager

	errCh chan error
}

func NewAgent(socketpath string, clientSet kubernetes.Interface, nodeName string, targetNs string) (*Agent, error) {
	containerRuntime, err := netns.NewContainerRuntime(socketpath)
	if err != nil {
		return nil, err
	}
	watcher := netns.NewWatcher(clientSet, containerRuntime, nodeName, targetNs)
	manager, err := bpf.NewBpfManager()
	if err != nil {
		return nil, err
	}
	return &Agent{watcher: watcher, errCh: make(chan error, 1), bpfManager: manager}, nil
}

func (a *Agent) Run(ctx context.Context) error {
	go a.startDebugServer()

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
			a.watcher.Stop()
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

func (a *Agent) startDebugServer() {
	http.HandleFunc("/debug/pods", func(w http.ResponseWriter, r *http.Request) {
		pods := a.watcher.GetAllPods()
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(pods); err != nil {
			log.Printf("[Agent] Failed to encode debug info: %v", err)
		}
	})

	http.HandleFunc("/debug/bpf", func(w http.ResponseWriter, r *http.Request) {
		// TODO: print bpf info here
	})

	log.Println("[Agent] Debug server listening on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Printf("[Agent] Debug server error: %v", err)
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
