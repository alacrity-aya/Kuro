package probe

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"kuro/internal/domain"
)

const (
	DialTimeout = 3 * time.Second
)

// Manager handles probe task lifecycle and executes TCP Connect probes.
type Manager struct {
	mu      sync.Mutex
	tasks   map[string]context.CancelFunc // taskID -> cancel
	metrics *MetricsStore
}

func NewManager(metrics *MetricsStore) *Manager {
	return &Manager{
		tasks:   make(map[string]context.CancelFunc),
		metrics: metrics,
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

// executeTCPProbe performs a single TCP Connect probe and records the result.
func (m *Manager) executeTCPProbe(task domain.ProbeTask) {
	target := fmt.Sprintf("%s:%d", task.DstIP, task.TargetPort)

	start := time.Now()
	conn, err := net.DialTimeout("tcp", target, DialTimeout)
	rtt := time.Since(start)

	if err != nil {
		m.metrics.RecordResult(task, 0, false)
		// Log at debug level — probe failures are expected during topology changes
		log.Printf("[ProbeManager] Probe failed %s -> %s: %v", task.SrcPod, task.DstPod, err)
		return
	}
	conn.Close()

	m.metrics.RecordResult(task, rtt, true)
}
