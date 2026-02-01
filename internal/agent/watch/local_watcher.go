// Package watch get netns handler from pod
package watch

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"kuro/internal/domain"

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

	eventCh chan domain.PodEvent
}

// NewLocalWatcher creates a watcher optimized for a specific Node and Namespace.
// Note: We inject ContainerRuntime here.
func NewLocalWatcher(client kubernetes.Interface, containerRuntime *ContainerRuntime, nodeName, targetNs string) *LocalWatcher {
	return &LocalWatcher{
		client:           client,
		nodeName:         nodeName,
		targetNs:         targetNs,
		containerRuntime: containerRuntime,
		stopCh:           make(chan struct{}),
		store:            make(map[string]*PodContext),
		eventCh:          make(chan domain.PodEvent, 100),
	}
}

// Start begins the watching process.
func (w *LocalWatcher) Start(ctx context.Context) error {
	log.Printf("[Watcher] INFO Initializing watcher for Node: %s, Namespace: %s", w.nodeName, w.targetNs)

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
			// Log minimal trace for debug if needed, usually too noisy
			w.handlePodAddOrUpdate(pod, "ADD")
		},
		UpdateFunc: func(oldObj, newObj any) {
			newPod := newObj.(*corev1.Pod)
			oldPod := oldObj.(*corev1.Pod)

			// Only update if ContainerID or IP changed (Networking changed)
			// OR if we don't have it in our store yet.
			newCid := getContainerID(newPod)
			oldCid := getContainerID(oldPod)

			if newPod.Status.PodIP != oldPod.Status.PodIP || newCid != oldCid {
				log.Printf("[Watcher] INFO Detected change for %s. IP: %s->%s, CID: %s->%s",
					newPod.Name, oldPod.Status.PodIP, newPod.Status.PodIP, oldCid, newCid)
				w.handlePodAddOrUpdate(newPod, "UPDATE")
			}
		},
		DeleteFunc: func(obj any) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					log.Printf("[Watcher] ERROR Could not get object from tombstone")
					return
				}
				pod, ok = tombstone.Obj.(*corev1.Pod)
				if !ok {
					log.Printf("[Watcher] ERROR Tombstone contained object that is not a Pod")
					return
				}
			}
			w.handlePodDelete(pod)
		},
	})

	go factory.Start(w.stopCh)

	log.Println("[Watcher] INFO Waiting for informer cache sync...")
	if !cache.WaitForCacheSync(w.stopCh, w.informer.HasSynced) {
		return fmt.Errorf("timed out waiting for caches to sync")
	}
	log.Println("[Watcher] INFO Cache synced successfully. Watcher is now active.")

	return nil
}

func (w *LocalWatcher) Stop() {
	log.Println("[Watcher] INFO Stopping watcher initiated...")

	// Clean up all open Netns handles before stopping
	w.mu.Lock()
	count := 0
	for name, ctx := range w.store {
		if ctx.NetnsHandle.IsOpen() {
			ctx.NetnsHandle.Close()
			count++
		}
		delete(w.store, name)
	}
	w.mu.Unlock()

	close(w.stopCh)
	log.Printf("[Watcher] INFO Stopped. Closed %d active Netns handles.", count)
}

// ================= Logic Handlers =================

func (w *LocalWatcher) handlePodAddOrUpdate(pod *corev1.Pod, source string) {
	// Skip if Pod is not running or has no IP yet
	if pod.Status.Phase != corev1.PodRunning || pod.Status.PodIP == "" {
		// Optional: Log verbose if needed, but skipping usually reduces noise
		return
	}

	info := extractPodInfo(pod)
	if info.ContainerID == "" {
		log.Printf("[Watcher] WARN Pod %s is running but ContainerID is missing. Skipping.", info.Name)
		return
	}

	log.Printf("[Watcher] INFO Handling %s event for Pod: %s | IP: %s | ContainerID: %s",
		source, info.Name, info.IP, info.ContainerID)

	// 1. Resolve Netns
	// Create a short-lived context for the Containerd call
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	handle, err := w.containerRuntime.GetNsByContainerID(ctx, info.ContainerID)
	if err != nil {
		log.Printf("[Watcher] ERROR Failed to resolve netns for Pod %s (CID: %s): %v", info.Name, info.ContainerID, err)
		return
	}

	vethName, vethIndex, err := w.containerRuntime.GetHostVethPair(handle)
	if err != nil {
		log.Printf("[Watcher] ERROR Failed to resolve host veth for Pod %s: %v. Closing handle.", info.Name, err)
		handle.Close()
		return
	}

	info.HostVeth = vethName
	info.HostIfIndex = vethIndex

	// 2. Update Store (Thread-Safe)
	w.mu.Lock()
	defer w.mu.Unlock()

	eventType := domain.EventAdd

	if oldCtx, exists := w.store[info.Name]; exists {
		oldCtx.NetnsHandle.Close()
		eventType = domain.EventModify
	}

	w.store[info.Name] = &PodContext{
		Info:        info,
		NetnsHandle: handle,
	}

	event := domain.PodEvent{
		Type:        eventType,
		PodName:     info.Name,
		Namespace:   info.Namespace,
		PodIP:       info.IP,
		ContainerID: info.ContainerID,
		HostIfIndex: int32(info.HostIfIndex),
	}

	select {
	case w.eventCh <- event:
	default:
		log.Printf("[Watcher] WARN Event channel full! Dropping event for Pod: %s", info.Name)
	}
}

func (w *LocalWatcher) handlePodDelete(pod *corev1.Pod) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if ctx, exists := w.store[pod.Name]; exists {
		// CRITICAL: Close the file descriptor
		ctx.NetnsHandle.Close()
		delete(w.store, pod.Name)

		log.Printf("[Watcher] INFO Cleaned up Pod %s. Netns handle closed and removed from store.", pod.Name)

		// Notify Agent
		// Use cached info (ctx.Info) because the pod object from DeleteFunc
		// might miss some details if it's a DeletedFinalStateUnknown object
		event := domain.PodEvent{
			Type:        domain.EventDelete,
			PodName:     ctx.Info.Name,
			Namespace:   ctx.Info.Namespace,
			PodIP:       ctx.Info.IP,
			ContainerID: ctx.Info.ContainerID,
			HostIfIndex: int32(ctx.Info.HostIfIndex),
		}

		select {
		case w.eventCh <- event:
		default:
			log.Printf("[Watcher] WARN Event channel full! Dropping DELETE event for Pod: %s", pod.Name)
		}
	} else {
		// Log debug only, usually happens if we never tracked the pod (e.g. it failed startup)
		log.Printf("[Watcher] INFO Received Delete event for untracked Pod: %s. Ignoring.", pod.Name)
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

func (w *LocalWatcher) GetEventCh() <-chan domain.PodEvent {
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
