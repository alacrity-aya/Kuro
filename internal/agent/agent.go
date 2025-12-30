package agent

import (
	"context"
	"log/slog"
	"sync"

	"github.com/alacrity-aya/Kuro/internal/agent/discovery"
)

type ContainerAgent struct {
	watcher *discovery.PodWatcher

	// Store pod information
	// key: HostIfIndex
	mu      sync.RWMutex
	targets map[int]discovery.TargetPod
}

func NewContainerAgent(watcher *discovery.PodWatcher) *ContainerAgent {
	return &ContainerAgent{
		watcher: watcher,
		targets: make(map[int]discovery.TargetPod),
	}
}

func (a *ContainerAgent) Run(ctx context.Context) {
	// start watcher
	events := a.watcher.Watch(ctx)

	for target := range events {
		a.handleEvent(target)
	}
}

func (a *ContainerAgent) handleEvent(target discovery.TargetPod) {
	a.mu.Lock()
	defer a.mu.Unlock()

	oldTarget, exists := a.targets[target.HostIfIndex]
	if exists {
		if oldTarget.ExpID == target.ExpID {
			slog.Debug("target already up-to-date", "pod", target.PodName)
			return
		}
		slog.Info("updating experiment rule", "pod", target.PodName, "oldID", oldTarget.ExpID, "newID", target.ExpID)
	}

	a.targets[target.HostIfIndex] = target

	// TODO: attach ebpf program
	slog.Debug("handle target", "pod", target.PodName, "experiment-id", target.ExpID, "iface-index", target.HostIfIndex)

	a.deployEBPF(target.HostIfIndex, target.ExpID)
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
