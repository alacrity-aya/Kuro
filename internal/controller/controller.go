package controller

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"

	"kuro/api/crd/v1alpha1"
	pb "kuro/api/proto/v1"
	"kuro/internal/controller/api"
	"kuro/internal/controller/k8s"
	"kuro/internal/controller/rpc"
	"kuro/internal/domain"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
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
		return fmt.Errorf("unable to create TrafficControl controller: %w", err)
	}

	// Setup liveness and readiness probes
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to set up health check: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to set up ready check: %w", err)
	}

	c.k8sManager = mgr
	return nil
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
		return nil
	}
}

// runGrpcServer internal helper method
func (c *ControllerManager) runGrpcServer() error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", c.grpcPort))
	if err != nil {
		return err
	}
	grpcServer := grpc.NewServer()
	rpcService := rpc.NewServer(c)
	pb.RegisterSimulationAgentServiceServer(grpcServer, rpcService)
	return grpcServer.Serve(lis)
}

// =============================================================
// Implementation of rpc.AgentManager Interface
// =============================================================

func (c *ControllerManager) RegisterAgent(nodeName string, sender domain.AgentSender) {
	c.activeAgents.Store(nodeName, sender)
	log.Printf("[Controller] Agent Registered: %s", nodeName)
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
	status := "Success"
	if !ack.Success {
		status = fmt.Sprintf("Failed (%s)", ack.Message)
	}
	log.Printf("[Ack] Node: %s, ID: %s, Status: %s", nodeName, ack.CommandID, status)
}

// =============================================================
// Business Logic Methods (Exposed to HTTP API & K8s Reconciler)
// =============================================================

func (c *ControllerManager) SendCommand(nodeName string, payload any) (string, error) {
	val, ok := c.activeAgents.Load(nodeName)
	if !ok {
		return "", fmt.Errorf("agent on node '%s' not connected", nodeName)
	}
	sender := val.(domain.AgentSender)

	cmdID := uuid.New().String()
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
