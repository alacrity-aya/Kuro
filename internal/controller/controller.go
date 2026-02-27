package controller

import (
	"context"
	"fmt"
	"log"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"kuro/api/crd/v1alpha1"
	pb "kuro/api/proto/v1"
	"kuro/internal/controller/api"
	"kuro/internal/controller/k8s"
	"kuro/internal/controller/rpc"
	"kuro/internal/domain"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

type ControllerManager struct {
	activeAgents sync.Map
	grpcPort     int
	httpPort     int
	metricsAddr  string
	k8sManager   ctrl.Manager
	scheme       *runtime.Scheme

	k8sClient  client.Client
	grpcServer *grpc.Server

	// Resync mechanism: batch + debounce to avoid API storm on Controller restart
	resyncQueue    chan string   // Node names pending resync
	resyncPending  sync.Map      // Dedup: nodeName -> bool (in queue or not)
	resyncDebounce time.Duration // Debounce interval
}

func NewControllerManager(grpcPort, httpPort int, metricsAddr string) *ControllerManager {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))

	return &ControllerManager{
		grpcPort:       grpcPort,
		httpPort:       httpPort,
		metricsAddr:    metricsAddr,
		scheme:         scheme,
		resyncQueue:    make(chan string, 1000), // Buffer for 1000 nodes
		resyncDebounce: 2 * time.Second,         // Wait 2s to collect reconnecting nodes
	}
}

func (c *ControllerManager) InitK8sManager() error {
	// Initialize the logger for the controller
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: c.scheme,
		Metrics: metricsserver.Options{
			BindAddress: c.metricsAddr,
		},
		HealthProbeBindAddress: ":8081",
		LeaderElection:         false, // Leader election disabled for dev/single instance
	})
	if err != nil {
		return fmt.Errorf("unable to start manager: %w", err)
	}

	// Register the Topology Reconciler
	if err = (&k8s.TopologyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to create Topology controller: %w", err)
	}

	// Register the TrafficControl Reconciler
	if err = (&k8s.TrafficControlReconciler{
		Client:       mgr.GetClient(),
		Scheme:       mgr.GetScheme(),
		AgentManager: c,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to create TraffgrpcServer *grpc.ServericControl controller: %w", err)
	}

	// Setup liveness and readiness probes
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to set up health check: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to set up ready check: %w", err)
	}

	c.k8sManager = mgr
	c.k8sClient = mgr.GetClient()
	return nil
}

func (c *ControllerManager) GetK8sClient() client.Client {
	return c.k8sClient
}

// Run starts all services. This method blocks until a signal is received or a critical error occurs.
func (c *ControllerManager) Run(ctx context.Context) error {
	// Ensure K8s Manager is initialized
	if c.k8sManager == nil {
		if err := c.InitK8sManager(); err != nil {
			return err
		}
	}

	errCh := make(chan error, 4)

	// 1. Start gRPC Server (Goroutine)
	go func() {
		log.Printf("[Controller] Starting gRPC Server on :%d", c.grpcPort)
		if err := c.runGrpcServer(); err != nil {
			errCh <- fmt.Errorf("gRPC server failed: %w", err)
		}
	}()

	// 2. Start HTTP API Server (Goroutine)
	go func() {
		log.Printf("[Controller] Starting HTTP API Server on :%d", c.httpPort)
		httpServer := api.NewHTTPServer(c, c.httpPort)
		if err := httpServer.Run(); err != nil {
			errCh <- fmt.Errorf("HTTP server failed: %w", err)
		}
	}()

	// 3. Start K8s Manager (Runs as goroutine to avoid blocking the select)
	go func() {
		log.Printf("[Controller] Starting K8s Manager")
		if err := c.k8sManager.Start(ctx); err != nil {
			errCh <- fmt.Errorf("K8s manager failed: %w", err)
		}
	}()

	// 4. Start Resync Worker (batch + debounce to avoid API storm)
	go func() {
		log.Printf("[Controller] Starting Resync Worker")
		c.startResyncWorker(ctx)
	}()

	// Wait for error or context cancellation
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Println("[Controller] Shutting down...")

		if c.grpcServer != nil {
			log.Println("[Controller] Stopping gRPC server immediately...")
			c.grpcServer.Stop()
		}

		return nil
	}
}

// runGrpcServer internal helper method
func (c *ControllerManager) runGrpcServer() error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", c.grpcPort))
	if err != nil {
		return err
	}

	c.grpcServer = grpc.NewServer()

	rpcService := rpc.NewServer(c)
	pb.RegisterSimulationAgentServiceServer(c.grpcServer, rpcService)

	return c.grpcServer.Serve(lis)
}

// =============================================================
// Implementation of rpc.AgentManager Interface
// =============================================================

func (c *ControllerManager) RegisterAgent(nodeName string, sender domain.AgentSender) {
	c.activeAgents.Store(nodeName, sender)
	log.Printf("[Controller] Agent Registered: %s", nodeName)

	// Enqueue for batch resync (avoids API storm on Controller restart)
	c.enqueueResync(nodeName)
}

// enqueueResync adds a node to the resync queue with deduplication
func (c *ControllerManager) enqueueResync(nodeName string) {
	// Dedup: skip if already pending
	if _, exists := c.resyncPending.LoadOrStore(nodeName, true); exists {
		return
	}

	select {
	case c.resyncQueue <- nodeName:
	default:
		log.Printf("[Controller] Warning: resync queue full, dropping %s", nodeName)
		c.resyncPending.Delete(nodeName)
	}
}

// startResyncWorker runs the background worker that processes resync requests in batches
func (c *ControllerManager) startResyncWorker(ctx context.Context) {
	batch := make([]string, 0, 100)
	timer := time.NewTimer(c.resyncDebounce)
	defer timer.Stop()

	for {
		select {
		case nodeName := <-c.resyncQueue:
			batch = append(batch, nodeName)
			// Process immediately if batch is large enough
			if len(batch) >= 100 {
				c.processResyncBatch(ctx, batch)
				batch = batch[:0]
				timer.Reset(c.resyncDebounce)
			}

		case <-timer.C:
			if len(batch) > 0 {
				c.processResyncBatch(ctx, batch)
				batch = batch[:0]
			}
			timer.Reset(c.resyncDebounce)

		case <-ctx.Done():
			// Process remaining batch before exit
			if len(batch) > 0 {
				c.processResyncBatch(ctx, batch)
			}
			return
		}
	}
}

// processResyncBatch processes a batch of nodes: fetches TrafficControls once and dispatches to all nodes
func (c *ControllerManager) processResyncBatch(ctx context.Context, nodes []string) {
	if len(nodes) == 0 {
		return
	}

	log.Printf("[Controller] Processing resync batch for %d nodes", len(nodes))

	// 1. Fetch all TrafficControls (only once for the entire batch)
	var tcList v1alpha1.TrafficControlList
	if err := c.k8sClient.List(ctx, &tcList); err != nil {
		log.Printf("[Controller] Failed to list TrafficControls for resync: %v", err)
		return
	}

	// 2. Fetch all Pods to build IP -> NodeName mapping
	var podList corev1.PodList
	if err := c.k8sClient.List(ctx, &podList, client.InNamespace("kuro-experiment")); err != nil {
		log.Printf("[Controller] Failed to list Pods for resync: %v", err)
		return
	}

	// 3. Build node -> pods mapping
	nodePods := make(map[string][]corev1.Pod)
	for _, pod := range podList.Items {
		if pod.Status.PodIP != "" && pod.Spec.NodeName != "" {
			nodePods[pod.Spec.NodeName] = append(nodePods[pod.Spec.NodeName], pod)
		}
	}

	// 4. For each TrafficControl, dispatch to relevant nodes
	for _, tc := range tcList.Items {
		if tc.DeletionTimestamp != nil {
			continue
		}

		// Parse policy once
		policyTemplate, err := k8s.ParseLinkPolicy(
			tc.Spec.Policy.Bandwidth,
			tc.Spec.Policy.Latency,
			tc.Spec.Policy.Jitter,
			tc.Spec.Policy.PacketLoss,
		)
		if err != nil {
			continue
		}

		// Find relevant nodes for this TrafficControl
		srcSelector, _ := metav1.LabelSelectorAsSelector(&tc.Spec.Source)
		dstSelector, _ := metav1.LabelSelectorAsSelector(&tc.Spec.Destination)

		for _, nodeName := range nodes {
			pods, ok := nodePods[nodeName]
			if !ok {
				continue
			}

			// Dispatch policies for pods on this node
			for _, srcPod := range pods {
				if srcPod.Status.PodIP == "" {
					continue
				}
				if !srcSelector.Matches(labels.Set(srcPod.Labels)) {
					continue
				}

				linkPolicy := policyTemplate
				linkPolicy.SrcIP = srcPod.Status.PodIP

				// Find destination pods
				for _, dstPod := range podList.Items {
					if dstPod.Status.PodIP == "" {
						continue
					}
					if !dstSelector.Matches(labels.Set(dstPod.Labels)) {
						continue
					}

					linkPolicy.DstIP = dstPod.Status.PodIP

					// Send to Agent
					if _, err := c.SendCommand(nodeName, tc.Name, linkPolicy); err != nil {
						log.Printf("[Controller] Failed to dispatch policy to %s: %v", nodeName, err)
					}
				}
			}
		}
	}

	// 4.5. Dispatch Probe Tasks for RTT measurement
	for _, nodeName := range nodes {
		if pods, ok := nodePods[nodeName]; ok {
			c.dispatchProbeTasksForNode(ctx, nodeName, pods, podList.Items)
		}
	}

	// 5. Clear pending flags
	for _, nodeName := range nodes {
		c.resyncPending.Delete(nodeName)
	}

	log.Printf("[Controller] Resync batch completed for %d nodes", len(nodes))
}

// dispatchProbeTasksForNode generates and dispatches probe tasks for pods on a given node.
// For each topology, it creates SIM and SYS probe tasks between all Pod pairs.
func (c *ControllerManager) dispatchProbeTasksForNode(ctx context.Context, nodeName string, nodePods []corev1.Pod, allPods []corev1.Pod) {
	for _, srcPod := range nodePods {
		if srcPod.Status.PodIP == "" {
			continue
		}

		for _, dstPod := range allPods {
			if dstPod.Status.PodIP == "" || dstPod.Name == srcPod.Name {
				continue
			}

			// SIM Probe: src -> dst on port 9090 (probe listener in Pod netns)
			simTask := domain.ProbeTask{
				TaskID:          fmt.Sprintf("probe-sim|%s|%s", srcPod.Name, dstPod.Name),
				SrcPod:          srcPod.Name,
				SrcIP:           srcPod.Status.PodIP,
				DstPod:          dstPod.Name,
				DstIP:           dstPod.Status.PodIP,
				Type:            domain.ProbeTypeSIM,
				IntervalSeconds: 5,
				TargetPort:      9090,
			}
			if _, err := c.SendCommand(nodeName, "probe", simTask); err != nil {
				log.Printf("[Controller] Failed to dispatch SIM probe task to %s: %v", nodeName, err)
			}

			// SYS Probe: src -> dst on port 9100 (agent metrics port on dst node)
			sysTask := domain.ProbeTask{
				TaskID:          fmt.Sprintf("probe-sys|%s|%s", srcPod.Name, dstPod.Name),
				SrcPod:          srcPod.Name,
				SrcIP:           srcPod.Status.PodIP,
				DstPod:          dstPod.Name,
				DstIP:           dstPod.Status.PodIP,
				Type:            domain.ProbeTypeSYS,
				IntervalSeconds: 5,
				TargetPort:      9100,
			}
			if _, err := c.SendCommand(nodeName, "probe", sysTask); err != nil {
				log.Printf("[Controller] Failed to dispatch SYS probe task to %s: %v", nodeName, err)
			}
		}
	}
}

func (c *ControllerManager) UnregisterAgent(nodeName string) {
	c.activeAgents.Delete(nodeName)
	log.Printf("[Controller] Agent Disconnected: %s", nodeName)
}

func (c *ControllerManager) HandleHeartbeat(nodeName string, hb domain.Heartbeat) {
	// Heartbeat logic implementation
}

func (c *ControllerManager) HandlePodEvent(nodeName string, event domain.PodEvent) {
	log.Printf("[Topology] Node %s report: Pod %s (%d) IP=%s",
		nodeName, event.PodName, event.Type, event.PodIP)
}

func (c *ControllerManager) HandleAck(nodeName string, ack domain.CommandAck) {
	log.Printf("[Ack] Node: %s, ID: %s, Success: %v", nodeName, ack.CommandID, ack.Success)

	// Parse CommandID and extract CRD Name
	parts := strings.Split(ack.CommandID, "|")
	if len(parts) < 2 {
		// If format is non-standard (e.g., manual API calls), just log it
		return
	}
	crdName := parts[0] // e.g., "weak-signal"

	// Start a goroutine to update K8s (avoids blocking gRPC)
	go c.updateTrafficControlStatus(crdName, nodeName, ack)
}

func (c *ControllerManager) updateTrafficControlStatus(name string, nodeName string, ack domain.CommandAck) {
	// Use Background context to prevent update failure due to parent context cancellation
	ctx := context.Background()

	// Define NamespacedName
	nn := types.NamespacedName{
		Name:      name,
		Namespace: "kuro-experiment", // Ideally passed through ACK payload or Reconcile Request; hardcoded for now
	}

	// ✅ Use RetryOnConflict to handle concurrent update conflicts
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		// 1. Must refetch the latest object from the API Server on every retry
		tc := &v1alpha1.TrafficControl{}
		if err := c.k8sClient.Get(ctx, nn, tc); err != nil {
			return err
		}

		// 2. Modify Status in memory
		// Modification must be based on the latest 'tc' object just retrieved

		// Avoid duplicate node entries (Idempotency)
		nodeExists := slices.Contains(tc.Status.ActiveNodes, nodeName)

		if ack.Success {
			if !nodeExists {
				tc.Status.ActiveNodes = append(tc.Status.ActiveNodes, nodeName)
			}
			tc.Status.Phase = "Active"
			// Simple Message aggregation logic
			tc.Status.Message = fmt.Sprintf("Sync success on %s (Total: %d)", nodeName, len(tc.Status.ActiveNodes))
		} else {
			// If failed, record error information
			tc.Status.Phase = "PartialFail"
			tc.Status.Message = fmt.Sprintf("Failed on %s: %s", nodeName, ack.Message)
		}

		// Update ObservedGeneration (Consistent with Reconcile logic)
		tc.Status.ObservedGeneration = tc.Generation

		// 3. Submit update
		return c.k8sClient.Status().Update(ctx, tc)
	})

	if err != nil {
		log.Printf("[Status] ❌ Failed to update status for %s after retries: %v", name, err)
	} else {
		log.Printf("[Status] ✅ Successfully updated %s status for node %s", name, nodeName)
	}
}

// =============================================================
// Business Logic Methods (Exposed to HTTP API & K8s Reconciler)
// =============================================================

func (c *ControllerManager) SendCommand(nodeName string, refKey string, payload any) (string, error) {
	val, ok := c.activeAgents.Load(nodeName)
	if !ok {
		return "", fmt.Errorf("agent on node '%s' not connected", nodeName)
	}
	sender := val.(domain.AgentSender)

	cmdID := fmt.Sprintf("%s|%s", refKey, uuid.New().String())

	cmd := domain.ControllerCommand{
		ID:      cmdID,
		Payload: payload,
	}

	if err := sender.Send(cmd); err != nil {
		return "", err
	}
	return cmdID, nil
}

func (c *ControllerManager) ListAgents() []string {
	agents := []string{}
	c.activeAgents.Range(func(key, value any) bool {
		agents = append(agents, key.(string))
		return true
	})
	return agents
}
