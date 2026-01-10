// Package agent
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

	pb "github.com/alacrity-aya/Kuro/api/proto/v1"
	"github.com/alacrity-aya/Kuro/internal/agent/discovery"
	"github.com/alacrity-aya/Kuro/internal/agent/manager"
	"github.com/alacrity-aya/Kuro/internal/agent/syncer"
	"github.com/alacrity-aya/Kuro/internal/spec"
	"github.com/vishvananda/netns"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/watch"
)

// Ensure ContainerAgent implements syncer.TaskExecutor
var _ syncer.TaskExecutor = (*ContainerAgent)(nil)

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
	// pods not applied rules yet
	desiredSpecs map[string]spec.Spec
}

func NewContainerAgent(watcher *discovery.PodWatcher, manager *manager.BpfManager) *ContainerAgent {
	agent := &ContainerAgent{
		watcher: watcher,
		manager: manager,

		targets:      make(map[int]discovery.TargetPod),
		podToIfIndex: make(map[string]int),
		desiredSpecs: make(map[string]spec.Spec),
	}

	syncer := syncer.NewSyncerServer(agent)
	agent.syncer = syncer

	return agent
}

func (a *ContainerAgent) Run(ctx context.Context, grpcAddr string) error {
	lis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", grpcAddr, err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterAgentServiceServer(grpcServer, a.syncer)

	go func() {
		slog.Info("Syncer gRPC server listening", "addr", grpcAddr)
		if err := grpcServer.Serve(lis); err != nil {
			slog.Error("gRPC server failed", "error", err)
		}
	}()

	go func() {
		<-ctx.Done()
		slog.Info("Stopping Syncer gRPC server...")
		grpcServer.GracefulStop()
	}()

	slog.Info("Starting Pod watcher loop")
	events := a.watcher.Watch(ctx)
	for event := range events {
		a.handleEvent(event)
	}

	return nil
}

// handleEvent update targets and podToIfIndex by message from watcher
func (a *ContainerAgent) handleEvent(event discovery.Event) {
	slog.Debug("handleEvent", "event", event)

	a.mu.Lock()

	defer a.mu.Unlock()
	podKey := event.Target.PodName

	switch event.Type {
	case watch.Added:

		shouldDeploy := true // TODO: what is the function of the following code snippet?
		if oldIdx, ok := a.podToIfIndex[podKey]; ok {
			if oldIdx == event.Target.HostIfIndex {
				if a.targets[oldIdx].ExpID == event.Target.ExpID {
					shouldDeploy = false
				}
			} else {
				a.cleanUp(oldIdx)
			}
		}

		slog.Debug("handleEvent type", "type", event.Type, "shouldDeploy", shouldDeploy)

		if shouldDeploy {
			a.targets[event.Target.HostIfIndex] = event.Target
			a.podToIfIndex[podKey] = event.Target.HostIfIndex

			if specItem, ok := a.desiredSpecs[podKey]; ok {
				slog.Info("Applying desired rule for discovered pod", "pod", podKey)

				specItem.IfaceIndex = event.Target.HostIfIndex
				specItem.NsHandle = event.Target.NetnsHandle

				go func(s spec.Spec) {
					if err := a.ApplyRules([]spec.Spec{s}); err != nil {
						slog.Error("Failed to apply desired rule", "pod", s.PodName, "error", err)
					} else {
						slog.Info("Successfully applied desired rule", "pod", s.PodName)
					}
				}(specItem)
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
	return a.manager.CollectStats()
}

func (a *ContainerAgent) Close() error {
	slog.Info("Stopping ContainerAgent...")
	var errs []error

	if a.watcher != nil {
		slog.Debug("Closing PodWatcher")
		a.watcher.Close()
	}

	if a.manager != nil {
		slog.Debug("Closing BpfManager")
		if err := a.manager.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close manager: %w", err))
		}
	}

	a.mu.Lock()
	a.targets = nil
	a.podToIfIndex = nil
	a.mu.Unlock()

	if len(errs) > 0 {
		return fmt.Errorf("agent close errors: %v", errs)
	}

	slog.Info("ContainerAgent stopped successfully")
	return nil
}

func (a *ContainerAgent) UpdateSpec(podName string, s spec.Spec) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.desiredSpecs == nil {
		a.desiredSpecs = make(map[string]spec.Spec)
	}
	a.desiredSpecs[podName] = s
	slog.Info("Spec stored in pending desired", "pod", podName)

	ifIndex, ok := a.podToIfIndex[podName]
	if !ok {
		// Case A: Pod not exists
		slog.Info("Spec saved, waiting for pod to appear", "pod", podName)
		return nil
	}

	// Case B: Pod exist
	target := a.targets[ifIndex]

	s.IfaceIndex = ifIndex
	s.NsHandle = target.NetnsHandle

	slog.Info("Pod is active, applying rule immediately", "pod", podName)
	if err := a.manager.Apply(s); err != nil {
		return err
	}

	return nil
}
