package controller

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "github.com/alacrity-aya/Kuro/api/proto/v1"
	"github.com/alacrity-aya/Kuro/internal/api/v1alpha1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type AgentClientPool struct {
	clients map[string]pb.AgentServiceClient
	conns   map[string]*grpc.ClientConn
	mu      sync.RWMutex
}

func NewAgentClientPool() *AgentClientPool {
	return &AgentClientPool{
		clients: make(map[string]pb.AgentServiceClient),
		conns:   make(map[string]*grpc.ClientConn),
	}
}

func (p *AgentClientPool) GetClient(nodeIP string) (pb.AgentServiceClient, error) {
	p.mu.RLock()
	client, ok := p.clients[nodeIP]
	p.mu.RUnlock()
	if ok {
		return client, nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if client, ok := p.clients[nodeIP]; ok {
		return client, nil
	}

	target := fmt.Sprintf("%s:50051", nodeIP)
	// TODO: add keepalive params here
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	newClient := pb.NewAgentServiceClient(conn)
	p.conns[nodeIP] = conn
	p.clients[nodeIP] = newClient
	return newClient, nil
}

type TopologyReconciler struct {
	KubeClient kubernetes.Interface
	Logger     *slog.Logger
	Pool       *AgentClientPool

	// trace current monitoring task
	// map[NodeIP]context.CancelFunc
	monitors  map[string]context.CancelFunc
	monitorMu sync.Mutex
}

func NewTopologyReconciler(client kubernetes.Interface, logger *slog.Logger) *TopologyReconciler {
	return &TopologyReconciler{
		KubeClient: client,
		Logger:     logger.With("controller", "TopologyReconciler"),
		Pool:       NewAgentClientPool(),
		monitors:   make(map[string]context.CancelFunc),
	}
}

func (r *TopologyReconciler) Reconcile(topo *v1alpha1.NetworkTopology) error {
	r.Logger.Info("Reconcile", "topology", topo.Name)

	nodeRequests := make(map[string][]*pb.WorkloadEmulation)
	nodeIPs := make(map[string]string)

	for _, link := range topo.Spec.Links {

		pod, err := r.KubeClient.CoreV1().Pods(topo.Namespace).Get(context.TODO(), link.Source, metav1.GetOptions{})
		if err != nil {
			r.Logger.Warn("Skipping link: source pod not found", "pod", link.Source)
			continue
		}

		if pod.Spec.NodeName == "" || pod.Status.HostIP == "" || pod.Status.PodIP == "" {
			r.Logger.Debug("Skipping link: pod not ready", "pod", link.Source)
			continue
		}

		nodeName := pod.Spec.NodeName
		nodeIPs[nodeName] = pod.Status.HostIP

		pbRule := r.buildPbRule(link, pod.Name, pod.Status.PodIP)

		nodeRequests[nodeName] = append(nodeRequests[nodeName], pbRule)
	}

	for nodeName, rules := range nodeRequests {
		nodeIP := nodeIPs[nodeName]

		client, err := r.Pool.GetClient(nodeIP)
		if err != nil {
			r.Logger.Error("unable to connect Agent", "node", nodeName, "error", err)
			continue
		}

		req := &pb.EmulationRequest{
			RequestId: fmt.Sprintf("%s-%d", topo.Name, time.Now().UnixNano()),
			Workloads: rules,
		}

		resp, err := client.ApplyEmulation(context.Background(), req)
		if err != nil {
			r.Logger.Error("gRPC ApplyEmulation failed", "node", nodeName, "error", err)
		} else {
			r.Logger.Info("rules successfully sent", "node", nodeName, "status", resp.Status)
		}

		r.ensureMonitorRunning(nodeName, nodeIP, client)
	}

	return nil
}

// ensureMonitorRunning Ensures that the monitoring Goroutine for this node is running.
func (r *TopologyReconciler) ensureMonitorRunning(nodeName, nodeIP string, client pb.AgentServiceClient) {
	r.monitorMu.Lock()
	defer r.monitorMu.Unlock()

	// If it's already being monitored, just return.
	if _, exists := r.monitors[nodeIP]; exists {
		return
	}

	r.Logger.Info(">>> Start real-time traffic monitoring", "node", nodeName, "ip", nodeIP)

	ctx, cancel := context.WithCancel(context.Background())
	r.monitors[nodeIP] = cancel

	go func() {
		defer func() {
			r.monitorMu.Lock()
			delete(r.monitors, nodeIP) // clean up marker on exit
			r.monitorMu.Unlock()
			cancel()
		}()

		stream, err := client.WatchStatus(ctx, &pb.WatchStatusRequest{IncludeMetrics: true})
		if err != nil {
			r.Logger.Error("starting WatchStatus failed", "node", nodeName, "err", err)
			return
		}

		for {
			report, err := stream.Recv()
			if err == io.EOF {
				r.Logger.Info("end of monitoring flow", "node", nodeName)
				return
			}
			if err != nil {
				// TODO: check here if the context is canceled and then not print the error.
				r.Logger.Error("Failed to read monitoring data", "node", nodeName, "err", err)
				return
			}

			for _, wl := range report.Workloads {
				stats := wl.TrafficStats
				// bps -> Mbps
				rateMbps := stats.SmoothRateBps * 8 / 1000000.0

				r.Logger.Info("📊 [MONITOR]",
					"node", nodeName,
					"pod", wl.PodName,
					"rate", fmt.Sprintf("%.2f Mbps", rateMbps),
					"drop_pkts", stats.TotalDroppedPackets,
					"total_bytes", stats.TotalAcceptedBytes,
				)
			}
		}
	}()
}

func (r *TopologyReconciler) buildPbRule(link v1alpha1.Link, podName string, podIP string) *pb.WorkloadEmulation {
	rateBps := parseBandwidth(link.QoS.Bandwidth)
	burstBytes := parseSize(link.QoS.Burst)
	delayMs := parseTimeMs(link.QoS.Latency)
	lossPpm := parseLoss(link.QoS.Loss)

	return &pb.WorkloadEmulation{
		PodName:   podName,
		IfaceName: "eth0", // TODO: why eth0 here?
		PodIp:     podIP,
		RateLimit: &pb.RateLimit{
			RateBps:    rateBps,
			BurstBytes: burstBytes,
		},
		Netem: &pb.Netem{
			LossPpm:  lossPpm,
			DelayMs:  delayMs,
			JitterMs: 0, // TODO: hanle jitter here
		},
	}
}

func parseBandwidth(s string) uint64 {
	s = strings.TrimSuffix(s, "Mbps")
	val, _ := strconv.ParseUint(s, 10, 64)
	return val * 1000 * 1000
}

func parseSize(s string) uint64 {
	s = strings.TrimSuffix(s, "KB")
	val, _ := strconv.ParseUint(s, 10, 64)
	return val * 1024
}

func parseTimeMs(s string) uint32 {
	s = strings.TrimSuffix(s, "ms")
	val, _ := strconv.ParseUint(s, 10, 32)
	return uint32(val)
}

func parseLoss(s string) uint32 {
	if s == "" {
		return 0
	}
	s = strings.TrimSuffix(s, "%")
	val, _ := strconv.ParseFloat(s, 64)
	return uint32(val * 10000)
}
