package controller

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	pb "github.com/alacrity-aya/Kuro/api/proto/v1"
	"github.com/alacrity-aya/Kuro/internal/controller/config"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type AgentStatusEvent struct {
	AgentAddr string
	Report    *pb.StatusReport
	Error     error
}

type ApplyResult struct {
	Response *pb.EmulationResponse
	Error    error
}

type AgentClient struct {
	pb.AgentServiceClient
	conn    *grpc.ClientConn
	addr    string
	podName string
}

type ControllerManager struct {
	mu        sync.RWMutex
	agents    map[string]*AgentClient // key: PodIP:Port
	k8sClient *kubernetes.Clientset
}

// Keepalive params
var kacp = keepalive.ClientParameters{
	Time:                10 * time.Second,
	Timeout:             time.Second,
	PermitWithoutStream: true,
}

func NewControllerManager(kubeconfigPath string) (*ControllerManager, error) {
	// initialize k8s client
	var config *rest.Config
	var err error

	if kubeconfigPath == "" {
		// In-Cluster
		slog.Info("Using in-cluster kubernetes config")
		config, err = rest.InClusterConfig()
	} else {
		// Out-of-Cluster
		slog.Info("Using local kubeconfig", "path", kubeconfigPath)
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to build kube config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	return &ControllerManager{
		agents:    make(map[string]*AgentClient),
		k8sClient: clientset,
	}, nil
}

// StartDiscovery starts to watch pod, maintain connection pool
func (m *ControllerManager) StartDiscovery(ctx context.Context, namespace string) error {
	slog.Info("Starting K8s discovery", "ns", namespace)

	watcher, err := m.k8sClient.CoreV1().Pods(namespace).Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to watch pods: %w", err)
	}

	go func() {
		defer watcher.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-watcher.ResultChan():
				if !ok {
					slog.Warn("K8s watch channel closed")
					return
				}

				pod, ok := event.Object.(*corev1.Pod)
				if !ok {
					continue
				}

				if pod.Status.Phase != corev1.PodRunning || pod.Status.PodIP == "" {
					continue
				}

				// assume agent port is 50051
				agentAddr := fmt.Sprintf("%s:50051", pod.Status.PodIP)

				switch event.Type {
				case "ADDED", "MODIFIED":
					_, err := m.getOrConnectAgent(agentAddr, pod.Name)
					if err != nil {
						slog.Error("Failed to connect to discovered agent", "addr", agentAddr, "err", err)
					} else {
						slog.Info("Agent discovered/updated", "pod", pod.Name, "addr", agentAddr)
					}

				case "DELETED":
					slog.Info("Agent pod deleted", "pod", pod.Name)
					m.RemoveAgent(agentAddr)
				}
			}
		}
	}()
	return nil
}

func (m *ControllerManager) getOrConnectAgent(addr string, podName string) (*AgentClient, error) {
	m.mu.RLock()
	client, ok := m.agents[addr]
	m.mu.RUnlock()
	if ok {
		return client, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double check
	if client, ok = m.agents[addr]; ok {
		return client, nil
	}

	// establish gRPC conection
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(kacp),
	)
	if err != nil {
		return nil, fmt.Errorf("did not connect to agent %s: %v", addr, err)
	}

	client = &AgentClient{
		AgentServiceClient: pb.NewAgentServiceClient(conn),
		conn:               conn,
		addr:               addr,
		podName:            podName,
	}
	m.agents[addr] = client
	return client, nil
}

func (m *ControllerManager) RemoveAgent(addr string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	client, ok := m.agents[addr]
	if !ok {
		return
	}
	client.conn.Close()
	delete(m.agents, addr)
	slog.Info("Agent connection removed", "addr", addr)
}

// ApplyConfig send config to all agents
func (m *ControllerManager) ApplyConfig(ctx context.Context, cfg *config.EmulationConfig) (map[string]ApplyResult, error) {
	// snapshot
	m.mu.RLock()
	activeAgents := make([]*AgentClient, 0, len(m.agents))
	for _, client := range m.agents {
		activeAgents = append(activeAgents, client)
	}
	m.mu.RUnlock()

	if len(activeAgents) == 0 {
		return nil, fmt.Errorf("no active agents found via discovery")
	}

	req := m.buildRequest(cfg)
	results := make(map[string]ApplyResult)
	var resMu sync.Mutex

	g, ctx := errgroup.WithContext(ctx)

	for _, client := range activeAgents {
		g.Go(func() error {
			subCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			resp, err := client.ApplyEmulation(subCtx, req)

			resMu.Lock()
			results[client.addr] = ApplyResult{Response: resp, Error: err}
			resMu.Unlock()

			if err != nil {
				slog.Error("Apply failed", "agent", client.addr, "err", err)
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return results, err
	}
	return results, nil
}

func (m *ControllerManager) MonitorAgents(ctx context.Context) (<-chan AgentStatusEvent, error) {
	outCh := make(chan AgentStatusEvent, 100)

	// Background coroutine: Periodically checks for new connections that need to be monitored
	go func() {
		monitored := make(map[string]bool)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.mu.RLock()
				for addr, client := range m.agents {
					if !monitored[addr] {
						monitored[addr] = true
						go m.monitorSingleAgent(ctx, client, outCh, func() {
						})
					}
				}
				m.mu.RUnlock()
			}
		}
	}()

	return outCh, nil
}

func (m *ControllerManager) monitorSingleAgent(ctx context.Context, client *AgentClient, outCh chan<- AgentStatusEvent, onExit func()) {
	defer onExit()

	slog.Info("Starting monitor stream", "agent", client.addr)
	stream, err := client.WatchStatus(ctx, &pb.WatchStatusRequest{IncludeMetrics: true})
	if err != nil {
		outCh <- AgentStatusEvent{AgentAddr: client.addr, Error: err}
		return
	}

	for {
		report, err := stream.Recv()
		if err != nil {
			slog.Error("Stream disconnected", "agent", client.addr, "err", err)
			// Here, the upper layer is notified and the process exits, awaiting reconnection logic.
			outCh <- AgentStatusEvent{AgentAddr: client.addr, Error: err}
			return
		}

		select {
		case outCh <- AgentStatusEvent{AgentAddr: client.addr, Report: report}:
		case <-ctx.Done():
			return
		}
	}
}

func (m *ControllerManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.agents {
		a.conn.Close()
	}
}

// buildRequest yaml -> protobuf
func (m *ControllerManager) buildRequest(cfg *config.EmulationConfig) *pb.EmulationRequest {
	req := &pb.EmulationRequest{
		RequestId:     uuid.New().String(),
		ConfigVersion: cfg.ConfigVersion,
		Workloads:     make([]*pb.WorkloadEmulation, 0, len(cfg.Workloads)),
	}

	for _, w := range cfg.Workloads {
		pbWorkload := &pb.WorkloadEmulation{
			PodName: w.PodName,
		}

		if w.RateLimit != nil {
			pbWorkload.RateLimit = &pb.RateLimit{
				RateBps:    w.RateLimit.RateBps,
				BurstBytes: w.RateLimit.BurstBytes,
			}
		}

		if w.Netem != nil {
			pbWorkload.Netem = &pb.Netem{
				DelayMs:  w.Netem.DelayMs,
				JitterMs: w.Netem.JitterMs,
				LossPpm:  w.Netem.LossPpm,
			}
		}

		req.Workloads = append(req.Workloads, pbWorkload)
	}

	return req
}
