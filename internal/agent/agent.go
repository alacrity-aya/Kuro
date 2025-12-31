package agent

import (
	"context"
	"log/slog"
	"sync"

	"github.com/alacrity-aya/Kuro/internal/agent/discovery"
	"k8s.io/apimachinery/pkg/watch"
)

type ContainerAgent struct {
	watcher *discovery.PodWatcher

	// Store pod information
	// key: HostIfIndex
	mu      sync.RWMutex
	targets map[int]discovery.TargetPod
	// key: podname
	podToIfIndex map[string]int
}

func NewContainerAgent(watcher *discovery.PodWatcher) *ContainerAgent {
	return &ContainerAgent{
		watcher:      watcher,
		targets:      make(map[int]discovery.TargetPod),
		podToIfIndex: make(map[string]int),
	}
}

func (a *ContainerAgent) Run(ctx context.Context) {
	// start watcher
	events := a.watcher.Watch(ctx)

	for event := range events {
		a.handleEvent(event)
	}
}

func (a *ContainerAgent) handleEvent(event discovery.Event) {
	a.mu.Lock()
	defer a.mu.Unlock()
	podKey := event.Target.PodName
	switch event.Type {

	case watch.Added:
		if oldIdx, ok := a.podToIfIndex[podKey]; ok {
			if oldIdx == event.Target.HostIfIndex {
				if a.targets[oldIdx].ExpID == event.Target.ExpID {
					return
				}
			} else {
				a.cleanUp(oldIdx)
			}
		}

		a.targets[event.Target.HostIfIndex] = event.Target
		a.podToIfIndex[podKey] = event.Target.HostIfIndex

		// TODO: put this out of mutex
		a.deployEBPF(event.Target.HostIfIndex, event.Target.ExpID)

	case watch.Deleted:
		ifIndex, exists := a.podToIfIndex[podKey]
		if !exists {
			return
		}

		a.cleanUp(ifIndex)

		delete(a.targets, ifIndex)
		delete(a.podToIfIndex, podKey)

		slog.Debug("delete targets entry", "pod", podKey, "ifIndex", ifIndex)
	}

	slog.Debug("handleEvent", "targets", a.targets, "podToIfIndex", a.podToIfIndex)
}

func (a *ContainerAgent) cleanUp(ifIndex int) {
	t, ok := a.targets[ifIndex]
	if !ok {
		return
	}

	// TODO: detach eBPF safely
	slog.Info("Removing eBPF rules", "ifIndex", ifIndex)

	if t.NetnsHandle.IsOpen() {
		t.NetnsHandle.Close()
	}
}

func (a *ContainerAgent) deployEBPF(ifIndex int, expID string) {
	slog.Info("deploying ebpf program", "ifIndex", ifIndex, "expID", expID)
}

func (a *ContainerAgent) GetTarget(ifIndex int) (discovery.TargetPod, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	t, ok := a.targets[ifIndex]
	return t, ok
}
