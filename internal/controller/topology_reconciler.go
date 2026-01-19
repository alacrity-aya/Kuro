package controller

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "github.com/alacrity-aya/Kuro/api/proto/v1"
	"github.com/alacrity-aya/Kuro/internal/api/v1alpha1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
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

func (p *AgentClientPool) RemoveClient(nodeIP string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if conn, exists := p.conns[nodeIP]; exists {
		conn.Close()
		delete(p.conns, nodeIP)
		delete(p.clients, nodeIP)
		slog.Info("Connection removed from pool", "node_ip", nodeIP)
	}
}

func (p *AgentClientPool) GetClient(nodeIP string) (pb.AgentServiceClient, error) {
	p.mu.RLock()
	client, exists := p.clients[nodeIP]
	conn, connExists := p.conns[nodeIP]
	p.mu.RUnlock()

	if exists && connExists {
		state := conn.GetState()
		if state == connectivity.Ready || state == connectivity.Idle {
			return client, nil
		}
		slog.Warn("Connection unhealthy, recreating...", "node_ip", nodeIP, "state", state)
		p.RemoveClient(nodeIP)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if client, ok := p.clients[nodeIP]; ok {
		return client, nil
	}

	target := fmt.Sprintf("%s:50051", nodeIP)

	kacp := keepalive.ClientParameters{
		Time:                10 * time.Second,
		Timeout:             time.Second * 2,
		PermitWithoutStream: true,
	}

	conn, err := grpc.NewClient(target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(kacp),
	)
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

	monitors  map[string]context.CancelFunc
	monitorMu sync.Mutex

	Hub        *StreamHub
	ipToName   map[string]string
	ipToNameMu sync.RWMutex
}

func NewTopologyReconciler(client kubernetes.Interface, logger *slog.Logger) *TopologyReconciler {
	hub := NewStreamHub()
	go hub.Run()

	go func() {
		http.HandleFunc("/ws/traffic", hub.HandleConnections)
		slog.Info("WebSocket server listening on :8081")
		if err := http.ListenAndServe(":8081", nil); err != nil {
			slog.Error("HTTP Server failed", "err", err)
		}
	}()

	return &TopologyReconciler{
		KubeClient: client,
		Logger:     logger.With("controller", "TopologyReconciler"),
		Pool:       NewAgentClientPool(),
		monitors:   make(map[string]context.CancelFunc),
		Hub:        hub,
		ipToName:   make(map[string]string),
	}
}

// PodInfo helps to resolve IP addresses
type PodInfo struct {
	NodeName string
	HostIP   string
	PodIP    string
}

func (r *TopologyReconciler) Reconcile(topo *v1alpha1.NetworkTopology) error {
	r.Logger.Info("Reconcile", "topology", topo.Name)

	// 1. Pre-fetch Pod Info for all Nodes to build an IP map
	podMap := make(map[string]PodInfo)
	for _, node := range topo.Spec.Nodes {

		r.ipToNameMu.Lock()
		pod, err := r.KubeClient.CoreV1().Pods(topo.Namespace).Get(context.TODO(), node.Name, metav1.GetOptions{})
		if err != nil {
			r.Logger.Warn("Skipping node: pod not found", "pod", node.Name)
			continue
		}
		if pod.Status.HostIP == "" || pod.Status.PodIP == "" {
			r.Logger.Debug("Skipping node: pod IPs not ready", "pod", node.Name)
			continue
		}
		podMap[node.Name] = PodInfo{
			NodeName: pod.Spec.NodeName,
			HostIP:   pod.Status.HostIP,
			PodIP:    pod.Status.PodIP,
		}

		r.ipToName[pod.Status.PodIP] = node.Name

		r.ipToNameMu.Unlock()
	}

	// 2. Aggregate rules by Source Pod
	// map[SourcePodName] -> WorkloadEmulation
	workloadConfigs := make(map[string]*pb.WorkloadEmulation)

	// Helper to get or init WorkloadEmulation
	getOrCreateWorkload := func(podName string, info PodInfo) *pb.WorkloadEmulation {
		if _, exists := workloadConfigs[podName]; !exists {
			// Construct Default Rule from Global Defaults
			defaultRate := parseBandwidth(topo.Spec.Defaults.BackgroundRate)
			defaultBurst := parseSize(topo.Spec.Defaults.BackgroundBurst)

			// Override if node specific config exists
			// (Assuming simplistic override logic for now based on topo structure)
			for _, n := range topo.Spec.Nodes {
				if n.Name == podName && n.Config != nil {
					if n.Config.BackgroundRate != "" {
						defaultRate = parseBandwidth(n.Config.BackgroundRate)
					}
				}
			}

			workloadConfigs[podName] = &pb.WorkloadEmulation{
				PodName:   podName,
				IfaceName: "eth0", // TODO: why eth0 here?
				PodIp:     info.PodIP,
				Rules:     []*pb.EmulationRule{},
				DefaultRule: &pb.EmulationRule{
					TargetIp: "", // Empty for default/background
					RateLimit: &pb.RateLimit{
						RateBps:    defaultRate,
						BurstBytes: defaultBurst,
					},
					Netem: &pb.Netem{}, // No default netem usually
				},
			}
		}
		return workloadConfigs[podName]
	}

	// 3. Process Links
	for _, link := range topo.Spec.Links {
		sourceInfo, ok := podMap[link.Source]
		if !ok {
			// Source pod not ready or not in nodes list
			continue
		}

		targetInfo, ok := podMap[link.Target]
		if !ok {
			r.Logger.Warn("Target pod not ready", "target", link.Target)
			continue
		}

		wl := getOrCreateWorkload(link.Source, sourceInfo)

		r.Logger.Debug("Creating Rule",
			"source_pod", link.Source,
			"target_pod", link.Target,
			"target_ip", targetInfo.PodIP,
		)

		// Create Rule
		rule := &pb.EmulationRule{
			TargetIp: targetInfo.PodIP,
			RateLimit: &pb.RateLimit{
				RateBps:    parseBandwidth(link.QoS.Bandwidth),
				BurstBytes: parseSize(link.QoS.Burst),
			},
			Netem: &pb.Netem{
				LossPpm:  parseLoss(link.QoS.Loss),
				DelayMs:  parseTimeMs(link.QoS.Latency),
				JitterMs: parseTimeMs(link.QoS.Jitter),
			},
		}
		wl.Rules = append(wl.Rules, rule)
	}

	// 4. Group by Agent (HostIP) and Send
	agentRequests := make(map[string]*pb.EmulationRequest)

	for podName, config := range workloadConfigs {
		hostIP := podMap[podName].HostIP
		if _, exists := agentRequests[hostIP]; !exists {
			agentRequests[hostIP] = &pb.EmulationRequest{
				RequestId: fmt.Sprintf("%s-%d", topo.Name, time.Now().UnixNano()),
				Workloads: []*pb.WorkloadEmulation{},
			}
		}
		agentRequests[hostIP].Workloads = append(agentRequests[hostIP].Workloads, config)
	}

	for agentIP, req := range agentRequests {
		client, err := r.Pool.GetClient(agentIP)
		if err != nil {
			r.Logger.Error("unable to connect Agent", "agent_ip", agentIP, "error", err)
			continue
		}

		resp, err := client.ApplyEmulation(context.Background(), req)
		if err != nil {
			r.Logger.Error("gRPC ApplyEmulation failed", "agent_ip", agentIP, "error", err)
			r.Pool.RemoveClient(agentIP)
		} else {
			r.Logger.Info("Rules sent successfully", "agent_ip", agentIP, "status", resp.Status)
		}

		// Use the node name of the first workload for logging purposes
		nodeName := ""
		if len(req.Workloads) > 0 {
			nodeName = podMap[req.Workloads[0].PodName].NodeName
		}
		r.ensureMonitorRunning(nodeName, agentIP, client)
	}

	return nil
}

func (r *TopologyReconciler) ensureMonitorRunning(nodeName, nodeIP string, client pb.AgentServiceClient) {
	r.monitorMu.Lock()
	defer r.monitorMu.Unlock()

	if _, exists := r.monitors[nodeIP]; exists {
		return
	}

	r.Logger.Info(">>> Start real-time traffic monitoring", "node", nodeName, "ip", nodeIP)

	ctx, cancel := context.WithCancel(context.Background())
	r.monitors[nodeIP] = cancel

	go func() {
		defer func() {
			r.monitorMu.Lock()
			delete(r.monitors, nodeIP)
			r.monitorMu.Unlock()
			cancel()
		}()

		stream, err := client.WatchStatus(ctx, &pb.WatchStatusRequest{IncludeMetrics: true})
		if err != nil {
			r.Logger.Error("starting WatchStatus failed", "node", nodeName, "err", err)
			r.Pool.RemoveClient(nodeIP)
			return
		}

		for {
			report, err := stream.Recv()
			if err == io.EOF {
				r.Logger.Info("end of monitoring flow", "node", nodeName)
				return
			}
			if err != nil {
				if strings.Contains(err.Error(), "context canceled") {
					return
				}
				r.Logger.Error("Failed to read monitoring data", "node", nodeName, "err", err)
				r.Pool.RemoveClient(nodeIP)
				return
			}

			update := TrafficUpdate{
				LinkUpdates: make(map[string]LinkStatsData),
			}
			hasUpdates := false
			now := time.Now().UnixMilli()

			for _, wl := range report.Workloads {
				stats := wl.TrafficStats
				if stats == nil {
					continue
				}

				sourcePod := wl.PodName

				// Iterate over per-link stats
				for _, linkStat := range stats.LinkStats {
					remoteIP := linkStat.RemoteIp

					r.ipToNameMu.RLock()
					targetName, found := r.ipToName[remoteIP]
					r.ipToNameMu.RUnlock()

					if !found {
						continue
					}

					linkID := fmt.Sprintf("link-%s-%s", sourcePod, targetName)

					if linkStat.Egress != nil {
						rateBps := linkStat.Egress.SmoothRateBps
						drops := linkStat.Egress.DroppedPackets

						update.LinkUpdates[linkID] = LinkStatsData{
							Timestamp: now,
							RxBps:     rateBps,
							TxBps:     rateBps,
							Drops:     drops,
						}
						hasUpdates = true

					}

					// Log Ingress (Upload / Rx from Host)
					if linkStat.Ingress != nil {
						rateMbps := linkStat.Ingress.SmoothRateBps * 8 / 1000000.0
						if rateMbps > 0 || linkStat.Ingress.DroppedPackets > 0 {
							r.Logger.Info("📊 [LINK-RX]",
								"node", nodeName,
								"pod", wl.PodName,
								"rate", fmt.Sprintf("%.2f Mbps", rateMbps),
								"drops", linkStat.Ingress.DroppedPackets,
							)
						}
					}

					// Log Egress (Download / Tx from Host)
					if linkStat.Egress != nil {
						rateMbps := linkStat.Egress.SmoothRateBps * 8 / 1000000.0
						if rateMbps > 0 || linkStat.Egress.DroppedPackets > 0 {
							r.Logger.Info("📊 [LINK-TX]",
								"node", nodeName,
								"pod", wl.PodName,
								"rate", fmt.Sprintf("%.2f Mbps", rateMbps),
								"drops", linkStat.Egress.DroppedPackets,
							)
						}
					}

					if hasUpdates {
						r.Hub.BroadcastTraffic(update)
					}
				}
			}
		}
	}()
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
