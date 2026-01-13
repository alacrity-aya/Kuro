package controller

import (
	"context"
	"fmt"
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

// AgentClientPool 简单的连接池，缓存 nodeName -> grpcClient
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

// GetClient 获取或创建连接到指定 Node 的 Agent 客户端
// 假设 Agent 以 DaemonSet 运行，监听 Node IP 的固定端口 (例如 50051)
func (p *AgentClientPool) GetClient(nodeIP string) (pb.AgentServiceClient, error) {
	p.mu.RLock()
	client, ok := p.clients[nodeIP]
	p.mu.RUnlock()
	if ok {
		return client, nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// 双重检查
	if client, ok := p.clients[nodeIP]; ok {
		return client, nil
	}

	// 建立新连接 (生产环境应添加 keepalive 等配置)
	target := fmt.Sprintf("%s:50051", nodeIP) // 假设 Agent 监听 50051
	conn, err := grpc.Dial(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
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
	Pool       *AgentClientPool // 新增连接池
}

func NewTopologyReconciler(client kubernetes.Interface, logger *slog.Logger) *TopologyReconciler {
	return &TopologyReconciler{
		KubeClient: client,
		Logger:     logger.With("controller", "TopologyReconciler"),
		Pool:       NewAgentClientPool(),
	}
}

func (r *TopologyReconciler) Reconcile(topo *v1alpha1.NetworkTopology) error {
	r.Logger.Info("开始计算并下发网络拓扑规则", "topology", topo.Name)

	// 按 Node 聚合请求： Map<NodeName, List<WorkloadEmulation>>
	// 这样同一个 Node 上的多个 Pod 规则可以一次 gRPC 发送
	nodeRequests := make(map[string][]*pb.WorkloadEmulation)
	// 记录 NodeName 到 NodeIP 的映射
	nodeIPs := make(map[string]string)

	for _, link := range topo.Spec.Links {
		// 1. 找 Source Pod
		pod, err := r.KubeClient.CoreV1().Pods(topo.Namespace).Get(context.TODO(), link.Source, metav1.GetOptions{})
		if err != nil {
			r.Logger.Warn("Skipping link: source pod not found", "pod", link.Source)
			continue
		}

		if pod.Spec.NodeName == "" || pod.Status.HostIP == "" {
			r.Logger.Debug("Skipping link: pod not scheduled", "pod", link.Source)
			continue
		}

		nodeName := pod.Spec.NodeName
		nodeIPs[nodeName] = pod.Status.HostIP // 使用 HostIP 访问 Node 上的 Agent

		// 2. 构建 Protobuf 对象
		pbRule := r.buildPbRule(link, pod.Name)

		// 3. 加入聚合列表
		nodeRequests[nodeName] = append(nodeRequests[nodeName], pbRule)
	}

	// 4. 真正下发
	for nodeName, rules := range nodeRequests {
		nodeIP := nodeIPs[nodeName]
		r.Logger.Info("正在向 Node 下发规则", "node", nodeName, "ip", nodeIP, "rule_count", len(rules))

		client, err := r.Pool.GetClient(nodeIP)
		if err != nil {
			r.Logger.Error("无法连接 Agent", "node", nodeName, "error", err)
			continue
		}

		req := &pb.EmulationRequest{
			RequestId: fmt.Sprintf("%s-%d", topo.Name, time.Now().UnixNano()),
			Workloads: rules,
		}

		// RPC 调用
		resp, err := client.ApplyEmulation(context.Background(), req)
		if err != nil {
			r.Logger.Error("gRPC ApplyEmulation 失败", "node", nodeName, "error", err)
		} else {
			r.Logger.Info("规则下发成功", "node", nodeName, "agent_msg", resp.Message, "status", resp.Status)
		}
	}

	return nil
}

func (r *TopologyReconciler) buildPbRule(link v1alpha1.Link, podName string) *pb.WorkloadEmulation {
	rateBps := parseBandwidth(link.QoS.Bandwidth)
	burstBytes := parseSize(link.QoS.Burst)
	delayMs := parseTimeMs(link.QoS.Latency)
	lossPpm := parseLoss(link.QoS.Loss)

	return &pb.WorkloadEmulation{
		PodName:   podName,
		IfaceName: "eth0", // 简化假设
		RateLimit: &pb.RateLimit{
			RateBps:    rateBps,
			BurstBytes: burstBytes,
		},
		Netem: &pb.Netem{
			LossPpm:  lossPpm,
			DelayMs:  delayMs,
			JitterMs: 0, // 可以在 yaml 中添加 jitter 字段支持
		},
	}
}

// ... 之前的 parseBandwidth 等辅助函数保持不变 ...
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
