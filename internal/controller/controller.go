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
}

func NewControllerManager(grpcPort, httpPort int, metricsAddr string) *ControllerManager {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))

	return &ControllerManager{
		grpcPort:    grpcPort,
		httpPort:    httpPort,
		metricsAddr: metricsAddr,
		scheme:      scheme,
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

	errCh := make(chan error, 3)

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

	// NEW: Actively trigger Reconcile to re-dispatch rules after Agent reconnects
	// We need to fetch all relevant TrafficControl rules and trigger a Reconcile.
	// Since manually creating ReconcileRequests in ControllerManager is complex,
	// a simple approach is to update the TrafficControl Annotations or invoke dispatch logic in memory.

	// Simplest implementation (without architectural changes):
	// Traverse all TrafficControls; if Source or Destination is on this Node, re-run Reconcile.
	go c.triggerResyncForNode(nodeName)
}

// FIXME:
// issue in triggerResyncForNode: When an Agent connects, you traverse ALL TrafficControl objects and patch them.
// Scenario: Suppose you have 50 TrafficControl rules and a 100-node cluster.
// If the Controller restarts, 100 nodes reconnect simultaneously.
// Consequence: Instantly triggers 50 * 100 = 5000 K8s API Patch requests.
// This triggers K8s Throttling, potentially overloads the API Server, and the Reconcile queue explodes.
func (c *ControllerManager) triggerResyncForNode(nodeName string) {
	ctx := context.Background()
	var tcList v1alpha1.TrafficControlList
	if err := c.k8sClient.List(ctx, &tcList); err != nil {
		log.Printf("Failed to list TrafficControls for resync: %v", err)
		return
	}

	for _, tc := range tcList.Items {
		// Simple trigger mechanism: Add an annotation to force a Generation change.
		// Alternatively, a more elegant way is using the EventChannel mechanism to notify the Reconciler.
		// For simplicity, and to avoid frequent API Server writes,
		// Recommendation: Reuse the traffic_controller logic directly (though this requires refactoring).

		// "Quick and dirty" method: Add a timestamp Annotation to the CRD to force Update -> Reconcile
		patch := client.MergeFrom(tc.DeepCopy())
		if tc.Annotations == nil {
			tc.Annotations = make(map[string]string)
		}
		tc.Annotations["kuro.io/resync-trigger"] = time.Now().String()
		c.k8sClient.Patch(ctx, &tc, patch)
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
