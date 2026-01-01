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
	"github.com/vishvananda/netns"
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
}

func NewContainerAgent(watcher *discovery.PodWatcher, manager *manager.BpfManager) *ContainerAgent {
	agent := &ContainerAgent{
		watcher: watcher,
		manager: manager,

		targets:      make(map[int]discovery.TargetPod),
		podToIfIndex: make(map[string]int),
	}

	syncer := syncer.NewSyncerServer(agent)
	agent.syncer = syncer

	return agent
}

func (a *ContainerAgent) Run(ctx context.Context) {
	// TODO: run syncer
	events := a.watcher.Watch(ctx)
	for event := range events {
		a.handleEvent(event)
	}
}

// handleEvent update targets and podToIfIndex by message from watcher
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

func (a *ContainerAgent) GetPodMetadata(podName string) (int, netns.NsHandle, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	idx, ok := a.podToIfIndex[podName]
	if !ok {
		return 0, -1, false
	}
	target := a.targets[idx]
	return idx, target.NetnsHandle, true
}

func (a *ContainerAgent) ApplyRules(specs []spec.Spec) error {
	return a.manager.Apply(specs...)
}

func (a *ContainerAgent) CollectAllStats() []manager.TrafficStats {
	return nil
}
