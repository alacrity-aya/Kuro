package probe

import (
	"context"
	"fmt"
	"log"
	"net"
	"runtime"
	"sync"
	"time"

	"kuro/internal/domain"

	"github.com/vishvananda/netns"
)

const (
	DialTimeout = 3 * time.Second
)

// NetnsResolver provides access to Pod network namespace handles.
// This decouples the probe manager from the watch package.
type NetnsResolver interface {
	// GetNetns returns the netns handle for a given pod name.
	// The caller MUST NOT close the handle — it is managed by the watcher.
	GetNetns(podName string) (netns.NsHandle, bool)
}

// Manager handles probe task lifecycle and executes TCP Connect probes.
type Manager struct {
	mu       sync.Mutex
	tasks    map[string]context.CancelFunc // taskID -> cancel
	metrics  *MetricsStore
	resolver NetnsResolver
}

func NewManager(metrics *MetricsStore, resolver NetnsResolver) *Manager {
	return &Manager{
		tasks:    make(map[string]context.CancelFunc),
		metrics:  metrics,
		resolver: resolver,
	}
}

// AddTask starts a periodic probe for the given task.
func (m *Manager) AddTask(task domain.ProbeTask) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Stop existing task with same ID (idempotent)
	if cancel, exists := m.tasks[task.TaskID]; exists {
		cancel()
	}

	interval := time.Duration(task.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second // Default 5s
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.tasks[task.TaskID] = cancel

	go m.probeLoop(ctx, task, interval)

	log.Printf("[ProbeManager] Started task %s: %s(%s) -> %s(%s) type=%s interval=%v port=%d",
		task.TaskID, task.SrcPod, task.SrcIP, task.DstPod, task.DstIP,
		task.Type, interval, task.TargetPort)

	return nil
}

// RemoveTask stops a running probe task.
func (m *Manager) RemoveTask(taskID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if cancel, exists := m.tasks[taskID]; exists {
		cancel()
		delete(m.tasks, taskID)
		m.metrics.RemoveTask(taskID)
		log.Printf("[ProbeManager] Removed task %s", taskID)
	}
}

// StopAll stops all running probe tasks.
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, cancel := range m.tasks {
		cancel()
		delete(m.tasks, id)
	}
	log.Println("[ProbeManager] All tasks stopped")
}

// probeLoop runs periodic TCP Connect probes for a single task.
func (m *Manager) probeLoop(ctx context.Context, task domain.ProbeTask, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run immediately on start
	m.executeTCPProbe(task)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.executeTCPProbe(task)
		}
	}
}

// executeTCPProbe performs a single TCP Connect probe from inside the source Pod's
// network namespace. This ensures the SYN packet traverses the Pod's eth0 egress
// where eBPF applies latency/jitter shaping, giving us an accurate RTT measurement.
func (m *Manager) executeTCPProbe(task domain.ProbeTask) {
	target := fmt.Sprintf("%s:%d", task.DstIP, task.TargetPort)

	// Resolve source Pod's network namespace
	srcNs, ok := m.resolver.GetNetns(task.SrcPod)
	if !ok {
		m.metrics.RecordResult(task, 0, false)
		log.Printf("[ProbeManager] Probe skipped %s -> %s: src pod %s netns not found",
			task.SrcPod, task.DstPod, task.SrcPod)
		return
	}

	if !srcNs.IsOpen() {
		m.metrics.RecordResult(task, 0, false)
		log.Printf("[ProbeManager] Probe skipped %s -> %s: src pod %s netns handle closed",
			task.SrcPod, task.DstPod, task.SrcPod)
		return
	}

	// Perform TCP dial inside the source Pod's netns.
	// We must lock the OS thread because netns is per-thread in Linux.
	rtt, err := m.dialInNetns(srcNs, target)

	if err != nil {
		m.metrics.RecordResult(task, 0, false)
		log.Printf("[ProbeManager] Probe failed %s -> %s: %v", task.SrcPod, task.DstPod, err)
		return
	}

	m.metrics.RecordResult(task, rtt, true)
}

// dialInNetns enters the given network namespace, performs a TCP connect to target,
// and returns the round-trip time. The caller's goroutine is temporarily locked to
// an OS thread while the namespace switch is active.
func (m *Manager) dialInNetns(targetNs netns.NsHandle, target string) (time.Duration, error) {
	// Lock OS thread — netns is per-thread
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save current (host) netns
	hostNs, err := netns.Get()
	if err != nil {
		return 0, fmt.Errorf("get host netns: %w", err)
	}
	defer hostNs.Close()

	// Enter source Pod's netns
	if err := netns.Set(targetNs); err != nil {
		return 0, fmt.Errorf("enter pod netns: %w", err)
	}

	// Dial TCP from inside Pod netns — SYN goes through Pod eth0 egress (eBPF hook)
	start := time.Now()
	conn, dialErr := net.DialTimeout("tcp", target, DialTimeout)
	rtt := time.Since(start)

	// ALWAYS restore host netns before returning, regardless of dial result
	if restoreErr := netns.Set(hostNs); restoreErr != nil {
		// This is critical — if we can't restore, the goroutine is stuck in wrong netns
		log.Printf("[ProbeManager] CRITICAL: failed to restore host netns: %v", restoreErr)
		if conn != nil {
			conn.Close()
		}
		return 0, fmt.Errorf("restore host netns: %w", restoreErr)
	}

	if dialErr != nil {
		return 0, dialErr
	}

	conn.Close()
	return rtt, nil
}
