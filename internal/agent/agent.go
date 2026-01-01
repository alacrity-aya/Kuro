// Package agent
package agent

import (
	"context"
	"log/slog"
	"sync"

	"github.com/alacrity-aya/Kuro/internal/agent/discovery"
	"github.com/alacrity-aya/Kuro/internal/agent/manager"
	"github.com/alacrity-aya/Kuro/internal/agent/syncer"
	"github.com/alacrity-aya/Kuro/internal/spec"
	"k8s.io/apimachinery/pkg/watch"
)

var _ syncer.TaskExecutor = (*ContainerAgent)(nil) // check

type ContainerAgent struct {
	watcher *discovery.PodWatcher
	manager *manager.BpfManager
	syncer  *syncer.SyncerServer

	// Store iface rule
	specs []spec.Spec

	// Store pod information
	mu sync.RWMutex
	// HostIfIndex -> TargetPod
	targets map[int]discovery.TargetPod
	// podname -> HostIfIndex
	podToIfIndex map[string]int

	deployChan chan discovery.TargetPod
}

func NewContainerAgent(watcher *discovery.PodWatcher, manager *manager.BpfManager) *ContainerAgent {
	return &ContainerAgent{
		watcher: watcher,
		manager: manager,

		targets:      make(map[int]discovery.TargetPod),
		podToIfIndex: make(map[string]int),
		deployChan:   make(chan discovery.TargetPod, 100),
	}
}

func (a *ContainerAgent) Run(ctx context.Context) {
	go a.worker(ctx)

	events := a.watcher.Watch(ctx)
	for event := range events {
		a.handleEvent(event)
	}
}

func (a *ContainerAgent) worker(ctx context.Context) {
	slog.Info("eBPF deployment worker started")
	for {
		select {
		case target := <-a.deployChan:
			a.attachBpfprogram(target.HostIfIndex, target.PodName)
		case <-ctx.Done():
			return
		}
	}
}

func (a *ContainerAgent) handleEvent(event discovery.Event) {
	a.mu.Lock()
	podKey := event.Target.PodName

	switch event.Type {
	case watch.Added:
		shouldDeploy := true
		if oldIdx, ok := a.podToIfIndex[podKey]; ok {
			if oldIdx == event.Target.HostIfIndex {
				if a.targets[oldIdx].ExpID == event.Target.ExpID {
					shouldDeploy = false
				}
			} else {
				a.cleanUp(oldIdx)
			}
		}

		if shouldDeploy {
			a.targets[event.Target.HostIfIndex] = event.Target
			a.podToIfIndex[podKey] = event.Target.HostIfIndex

			select {
			case a.deployChan <- event.Target:
			default:
				slog.Error("Deploy channel full, dropping event", "pod", podKey)
			}
		}

	case watch.Deleted:
		ifIndex, exists := a.podToIfIndex[podKey]
		if exists {
			a.cleanUp(ifIndex)
			delete(a.targets, ifIndex)
			delete(a.podToIfIndex, podKey)
		}
	}
	a.mu.Unlock()
}

func (a *ContainerAgent) cleanUp(ifIndex int) {
	t, ok := a.targets[ifIndex]
	if !ok {
		return
	}

	slog.Info("Removing eBPF rules", "ifIndex", ifIndex)
	err := a.manager.CleanUp(ifIndex)
	if err != nil {
		slog.Error("Clean up ebpf error", "ifIndex", ifIndex, "error", err)
	}

	if t.NetnsHandle.IsOpen() {
		t.NetnsHandle.Close()
	}
}

func (a *ContainerAgent) attachBpfprogram(ifIndex int, podName string) {
	slog.Info("deploying ebpf program", "ifIndex", ifIndex, "podName", podName)

	err := a.manager.Attach(ifIndex)
	if err != nil {
		slog.Error("Attach ebpf program error", "ifIndex", ifIndex, "error", err)
	}
}

func (a *ContainerAgent) GetTarget(ifIndex int) (discovery.TargetPod, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	t, ok := a.targets[ifIndex]
	return t, ok
}
