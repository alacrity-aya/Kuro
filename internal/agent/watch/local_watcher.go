// Package watch get netns handler from pod
package watch

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	pb "kuro/api/v1"

	"github.com/vishvananda/netns"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// PodInfo encapsulates the essential information needed for the data plane.
type PodInfo struct {
	Name        string
	IP          string
	ContainerID string
	NodeName    string
	Namespace   string // pod netns
	HostVeth    string // host side veth name
	HostIfIndex int    // host side veth index
}

// PodContext holds the Pod metadata AND the active Netns handle.
// This is the actual object we want to store in memory.
type PodContext struct {
	Info        *PodInfo
	NetnsHandle netns.NsHandle // The open file descriptor for the namespace
}

// LocalWatcher manages the local cache of Pods and notifies on changes.
type LocalWatcher struct {
	client   kubernetes.Interface
	informer cache.SharedIndexInformer
	stopCh   chan struct{}
	nodeName string
	targetNs string

	// Dependencies
	containerRuntime *ContainerRuntime

	// Custom In-Memory Storage
	mu    sync.RWMutex
	store map[string]*PodContext // Key: PodName (since we are scoped to 1 namespace)

	eventCh chan *pb.PodLifecycleEvent
}

// NewLocolWatcher creates a watcher optimized for a specific Node and Namespace.
// Note: We inject ContainerRuntime here.
func NewLocolWatcher(client kubernetes.Interface, containerRuntime *ContainerRuntime, nodeName, targetNs string) *LocalWatcher {
	return &LocalWatcher{
		client:           client,
		nodeName:         nodeName,
		targetNs:         targetNs,
		containerRuntime: containerRuntime,
		stopCh:           make(chan struct{}),
		store:            make(map[string]*PodContext),
		eventCh:          make(chan *pb.PodLifecycleEvent, 100), // Buffer size 100
	}
}

// Start begins the watching process.
func (w *LocalWatcher) Start(ctx context.Context) error {
	tweakListOptions := func(options *metav1.ListOptions) {
		fs := fields.OneTermEqualSelector("spec.nodeName", w.nodeName)
		options.FieldSelector = fs.String()
	}

	factory := informers.NewSharedInformerFactoryWithOptions(
		w.client,
		10*time.Minute,
		informers.WithNamespace(w.targetNs),
		informers.WithTweakListOptions(tweakListOptions),
	)

	podInformer := factory.Core().V1().Pods()
	w.informer = podInformer.Informer()

	// Register Event Handlers
	w.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			pod := obj.(*corev1.Pod)
			w.handlePodAddOrUpdate(pod)
		},
		UpdateFunc: func(oldObj, newObj any) {
			newPod := newObj.(*corev1.Pod)
			oldPod := oldObj.(*corev1.Pod)

			// Only update if ContainerID or IP changed (Networking changed)
			// OR if we don't have it in our store yet.
			if newPod.Status.PodIP != oldPod.Status.PodIP ||
				getContainerID(newPod) != getContainerID(oldPod) {
				w.handlePodAddOrUpdate(newPod)
			}
		},
		DeleteFunc: func(obj any) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					return
				}
				pod, ok = tombstone.Obj.(*corev1.Pod)
				if !ok {
					return
				}
			}
			w.handlePodDelete(pod)
		},
	})

	go factory.Start(w.stopCh)

	fmt.Println("[Watcher] Waiting for cache sync...")
	if !cache.WaitForCacheSync(w.stopCh, w.informer.HasSynced) {
		return fmt.Errorf("timed out waiting for caches to sync")
	}
	fmt.Println("[Watcher] Cache synced successfully.")

	return nil
}

func (w *LocalWatcher) Stop() {
	// Clean up all open Netns handles before stopping
	w.mu.Lock()
	for name, ctx := range w.store {
		if ctx.NetnsHandle.IsOpen() {
			ctx.NetnsHandle.Close()
		}
		delete(w.store, name)
	}
	w.mu.Unlock()

	close(w.stopCh)
}

// ================= Logic Handlers =================

func (w *LocalWatcher) handlePodAddOrUpdate(pod *corev1.Pod) {
	// Skip if Pod is not running or has no IP yet
	if pod.Status.Phase != corev1.PodRunning || pod.Status.PodIP == "" {
		return
	}

	info := extractPodInfo(pod)
	if info.ContainerID == "" {
		// Container not ready yet
		return
	}

	// 1. Resolve Netns
	// Create a short-lived context for the Containerd call
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	handle, err := w.containerRuntime.GetNsByContainerID(ctx, info.ContainerID)
	if err != nil {
		fmt.Printf("[Watcher] Failed to resolve netns for %s: %v\n", info.Name, err)
		return
	}

	vethName, vethIndex, err := w.containerRuntime.GetHostVethPair(handle)
	if err != nil {
		fmt.Printf("[Watcher] Failed to resolve host veth for %s: %v\n", info.Name, err)
		handle.Close()
		return
	}

	info.HostVeth = vethName
	info.HostIfIndex = vethIndex

	// 2. Update Store (Thread-Safe)
	w.mu.Lock()
	defer w.mu.Unlock()

	eventType := pb.PodLifecycleEvent_ADDED

	// If entry exists, close the OLD handle to prevent FD leak
	if oldCtx, exists := w.store[info.Name]; exists {
		oldCtx.NetnsHandle.Close()
		eventType = pb.PodLifecycleEvent_MODIFIED
		fmt.Printf("[Watcher] Updated Netns for %s\n", info.Name)
	} else {
		fmt.Printf("[Watcher] Added Netns for %s\n", info.Name)
	}

	w.store[info.Name] = &PodContext{
		Info:        info,
		NetnsHandle: handle,
	}

	// 3. Notify Agent
	event := &pb.PodLifecycleEvent{
		Type:        eventType,
		PodName:     info.Name,
		Namespace:   info.Namespace,
		PodIp:       info.IP,
		ContainerId: info.ContainerID,
		HostIfindex: int32(info.HostIfIndex),
	}

	// Non-blocking send to avoid holding the lock or stalling informer
	select {
	case w.eventCh <- event:
	default:
		fmt.Printf("[Watcher] Warning: Event channel full, dropping event for %s\n", info.Name)
	}
}

func (w *LocalWatcher) handlePodDelete(pod *corev1.Pod) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if ctx, exists := w.store[pod.Name]; exists {
		// CRITICAL: Close the file descriptor
		ctx.NetnsHandle.Close()
		delete(w.store, pod.Name)
		fmt.Printf("[Watcher] Cleaned up %s\n", pod.Name)

		// Notify Agent
		// Use cached info (ctx.Info) because the pod object from DeleteFunc
		// might miss some details if it's a DeletedFinalStateUnknown object
		event := &pb.PodLifecycleEvent{
			Type:        pb.PodLifecycleEvent_DELETED,
			PodName:     ctx.Info.Name,
			Namespace:   ctx.Info.Namespace,
			PodIp:       ctx.Info.IP,
			ContainerId: ctx.Info.ContainerID,
			HostIfindex: int32(ctx.Info.HostIfIndex),
		}

		select {
		case w.eventCh <- event:
		default:
			fmt.Printf("[Watcher] Warning: Event channel full, dropping delete event for %s\n", pod.Name)
		}
	}
}

// ================= Public APIs =================

// GetPodContext returns the PodInfo and NetnsHandle for a given pod name.
// The caller should NOT close the handle, as it is managed by the Watcher.
// If you need to keep the handle for long operations, consider duplicating it.
func (w *LocalWatcher) GetPodContext(podName string) (*PodContext, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	ctx, ok := w.store[podName]
	return ctx, ok
}

// GetAllPods returns a snapshot of all tracked pods.
func (w *LocalWatcher) GetAllPods() []*PodContext {
	w.mu.RLock()
	defer w.mu.RUnlock()

	list := make([]*PodContext, 0, len(w.store))
	for _, ctx := range w.store {
		list = append(list, ctx)
	}
	return list
}

func (w *LocalWatcher) GetEventCh() <-chan *pb.PodLifecycleEvent {
	return w.eventCh
}

// ================= Helpers =================

func extractPodInfo(pod *corev1.Pod) *PodInfo {
	cid := getContainerID(pod)
	return &PodInfo{
		Name:        pod.Name,
		Namespace:   pod.Namespace,
		IP:          pod.Status.PodIP,
		ContainerID: cid,
		NodeName:    pod.Spec.NodeName,
		// HostVeth and HostIfIndex : handlePodAddOrUpdate
	}
}

func getContainerID(pod *corev1.Pod) string {
	if len(pod.Status.ContainerStatuses) > 0 {
		rawID := pod.Status.ContainerStatuses[0].ContainerID
		parts := strings.Split(rawID, "://")
		if len(parts) > 1 {
			return parts[1]
		}
		return rawID
	}
	return ""
}
