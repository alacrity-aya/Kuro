package watch

import (
	"context"
	"fmt"
	"log"
	"time"

	"kuro/internal/agent/bpf"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// PeerWatcher watches ALL pods in the target namespace (across the cluster)
// and updates the BPF whitelist map with their IPs.
type PeerWatcher struct {
	client     kubernetes.Interface
	informer   cache.SharedIndexInformer
	stopCh     chan struct{}
	targetNs   string
	bpfManager *bpf.BpfManager
}

func NewPeerWatcher(client kubernetes.Interface, bpfManager *bpf.BpfManager, targetNs string) *PeerWatcher {
	return &PeerWatcher{
		client:     client,
		targetNs:   targetNs,
		bpfManager: bpfManager,
		stopCh:     make(chan struct{}),
	}
}

func (w *PeerWatcher) Start(ctx context.Context) error {
	// Create a shared informer factory that watches the target namespace
	// Unlike the main Watcher, we DO NOT filter by NodeName.
	factory := informers.NewSharedInformerFactoryWithOptions(
		w.client,
		5*time.Minute, // Resync period
		informers.WithNamespace(w.targetNs),
	)

	podInformer := factory.Core().V1().Pods()
	w.informer = podInformer.Informer()

	// Register Handlers
	w.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			pod := obj.(*corev1.Pod)
			w.handleUpdate(pod)
		},
		UpdateFunc: func(oldObj, newObj any) {
			newPod := newObj.(*corev1.Pod)
			// Optimize: Only update if IP changed
			if newPod.Status.PodIP != "" {
				w.handleUpdate(newPod)
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
			w.handleDelete(pod)
		},
	})

	log.Printf("[PeerWatcher] Starting global peer watcher for namespace: %s", w.targetNs)
	go factory.Start(w.stopCh)

	if !cache.WaitForCacheSync(w.stopCh, w.informer.HasSynced) {
		return fmt.Errorf("timed out waiting for peer caches to sync")
	}
	log.Println("[PeerWatcher] Cache synced.")

	return nil
}

func (w *PeerWatcher) Stop() {
	close(w.stopCh)
}

func (w *PeerWatcher) handleUpdate(pod *corev1.Pod) {
	// Only care about running pods with IPs
	if pod.Status.PodIP == "" {
		return
	}

	// Inject into BPF Map
	if err := w.bpfManager.AddPeer(pod.Status.PodIP); err != nil {
		log.Printf("[PeerWatcher] Failed to add peer IP %s: %v", pod.Status.PodIP, err)
	}
}

func (w *PeerWatcher) handleDelete(pod *corev1.Pod) {
	if pod.Status.PodIP == "" {
		return
	}

	// Remove from BPF Map
	if err := w.bpfManager.RemovePeer(pod.Status.PodIP); err != nil {
		log.Printf("[PeerWatcher] Failed to remove peer IP %s: %v", pod.Status.PodIP, err)
	}
}
