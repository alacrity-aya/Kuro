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

	// Updated API: Set Upload and Download limits separately
	// Usage:
	//   curl "http://localhost:8080/ops/limit?up=1048576&down=2097152"  (1MB/s UP, 2MB/s DOWN)
	//   curl "http://localhost:8080/ops/limit?up=0&down=0"              (Unlimited)
	http.HandleFunc("/ops/limit", func(w http.ResponseWriter, r *http.Request) {
		// 1. Parse Query Parameters
		q := r.URL.Query()
		upStr := q.Get("up")
		downStr := q.Get("down")

		var upLimit, downLimit uint64

		if upStr != "" {
			fmt.Sscanf(upStr, "%d", &upLimit)
		}
		if downStr != "" {
			fmt.Sscanf(downStr, "%d", &downLimit)
		}

		log.Printf("[Agent API] Request: Set LIMIT -> Upload: %d Bps, Download: %d Bps", upLimit, downLimit)

		// 2. Apply to all tracked pods
		pods := a.watcher.GetAllPods()
		results := make(map[string]string)

		for _, p := range pods {
			// Skip invalid host interface indices
			if p.Info.HostIfIndex == 0 {
				results[p.Info.Name] = "Skipped (No HostIfIndex)"
				continue
			}

			// 3. Get Pod Context to retrieve the Netns Handle
			// We need the latest handle because it might have changed (e.g., pod restart)
			podCtx, ok := a.watcher.GetPodContext(p.Info.Name)
			if !ok {
				results[p.Info.Name] = "Skipped (Context not found)"
				continue
			}

			// Ensure handle is open/valid before passing to BPF manager
			if !podCtx.NetnsHandle.IsOpen() {
				results[p.Info.Name] = "Skipped (Netns Closed)"
				continue
			}

			// 4. Attach BPF Programs (Double-sided)
			// Pass the Netns Handle so the manager can enter the pod
			if err := a.bpfManager.AddPod(p.Info.Name, p.Info.HostIfIndex, podCtx.NetnsHandle); err != nil {
				errMsg := fmt.Sprintf("Failed to attach BPF: %v", err)
				log.Printf("[Agent API] %s: %s", p.Info.Name, errMsg)
				results[p.Info.Name] = errMsg
				continue
			}

			// 5. Update Rate Limits
			if err := a.bpfManager.UpdateRule(p.Info.HostIfIndex, upLimit, downLimit); err != nil {
				errMsg := fmt.Sprintf("Failed to update rule: %v", err)
				log.Printf("[Agent API] %s: %s", p.Info.Name, errMsg)
				results[p.Info.Name] = errMsg
				continue
			}

			// Success Message
			statusMsg := fmt.Sprintf("Success (Up: %d, Down: %d)", upLimit, downLimit)
			if upLimit == 0 && downLimit == 0 {
				statusMsg = "Success (Unlimited)"
			}
			results[p.Info.Name] = statusMsg
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(results); err != nil {
			log.Printf("[Agent API] Failed to encode response: %v", err)
		}
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
