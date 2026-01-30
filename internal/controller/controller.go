package controller

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"

	pb "kuro/api/v1"
	"kuro/internal/controller/rpc"

	"github.com/google/uuid"
	"google.golang.org/grpc"
)

// AgentSession wraps the gRPC stream with a mutex to ensure thread-safety
// when sending commands from concurrent HTTP requests.
type AgentSession struct {
	stream pb.SimulationAgentService_ControlStreamServer
	mu     sync.Mutex
	// We can add metadata here (LastSeen, IP, etc.)
}

// SendSafe is a thread-safe wrapper for sending commands to the stream.
func (s *AgentSession) SendSafe(cmd *pb.ControllerCmd) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stream.Send(cmd)
}

// ControllerManager is the central logic unit.
type ControllerManager struct {
	// activeAgents maps NodeName -> *AgentSession
	activeAgents sync.Map
	grpcPort     int
	httpPort     int
}

// NewControllerManager creates the manager.
func NewControllerManager(grpcPort, httpPort int) *ControllerManager {
	return &ControllerManager{
		grpcPort: grpcPort,
		httpPort: httpPort,
	}
}

// Run starts both gRPC and HTTP servers.
func (c *ControllerManager) Run() error {
	// 1. Start gRPC Server
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", c.grpcPort))
	if err != nil {
		return fmt.Errorf("failed to listen on grpc port %d: %w", c.grpcPort, err)
	}

	grpcServer := grpc.NewServer()
	// Initialize our RPC logic implementation
	rpcService := rpc.NewServer(c)
	pb.RegisterSimulationAgentServiceServer(grpcServer, rpcService)

	go func() {
		log.Printf("[Controller] gRPC Server listening on :%d", c.grpcPort)
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("gRPC serve failed: %v", err)
		}
	}()

	// 2. Start HTTP Server
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/policy/pod", c.ApplyPodPolicyAPI)
	mux.HandleFunc("/api/v1/policy/node", c.ApplyNodePolicyAPI)
	mux.HandleFunc("/api/v1/whitelist", c.SyncWhitelistAPI)
	// Add a simple status endpoint
	mux.HandleFunc("/api/v1/agents", c.ListAgentsAPI)

	log.Printf("[Controller] HTTP API listening on :%d", c.httpPort)
	return http.ListenAndServe(fmt.Sprintf(":%d", c.httpPort), mux)
}

// =============================================================
// Implementation of rpc.AgentManager Interface
// =============================================================

func (c *ControllerManager) RegisterAgent(nodeName string, stream pb.SimulationAgentService_ControlStreamServer) {
	session := &AgentSession{
		stream: stream,
	}
	c.activeAgents.Store(nodeName, session)
}

func (c *ControllerManager) UnregisterAgent(nodeName string) {
	c.activeAgents.Delete(nodeName)
}

func (c *ControllerManager) HandleHeartbeat(nodeName string, hb *pb.Heartbeat) {
	// In a real system, you would update a database or in-memory state store here.
	// For now, we just log it for debug visibility.
	// log.Printf("[Heartbeat] Node: %s, Pods: %d", nodeName, hb.ManagedPodCount)
}

func (c *ControllerManager) HandlePodEvent(nodeName string, event *pb.PodLifecycleEvent) {
	log.Printf("[Topology] Node %s report: Pod %s (%s) -> %s",
		nodeName, event.PodName, event.PodIp, event.Type)
	// TODO: Update global topology graph in database
}

func (c *ControllerManager) HandleAck(nodeName string, ack *pb.CommandAck) {
	status := "Success"
	if !ack.Success {
		status = fmt.Sprintf("Failed (%s)", ack.Message)
	}
	log.Printf("[Command Ack] Node: %s, ID: %s, Status: %s", nodeName, ack.CommandId, status)
}

// =============================================================
// HTTP Handlers (Control Plane)
// =============================================================

func (c *ControllerManager) sendCommandToNode(nodeName string, cmd *pb.ControllerCmd) error {
	val, ok := c.activeAgents.Load(nodeName)
	if !ok {
		return fmt.Errorf("agent on node '%s' not connected", nodeName)
	}

	session := val.(*AgentSession)
	if err := session.SendSafe(cmd); err != nil {
		return fmt.Errorf("failed to send gRPC command: %w", err)
	}
	return nil
}

// ListAgentsAPI returns currently connected agents
func (c *ControllerManager) ListAgentsAPI(w http.ResponseWriter, r *http.Request) {
	agents := []string{}
	c.activeAgents.Range(func(key, value any) bool {
		agents = append(agents, key.(string))
		return true
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"count": len(agents),
		"nodes": agents,
	})
}

func (c *ControllerManager) ApplyPodPolicyAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type Rate struct {
		Upload   uint64 `json:"upload"`
		Download uint64 `json:"download"`
	}
	var req struct {
		NodeName  string `json:"node_name"`
		PodName   string `json:"pod_name"`
		Namespace string `json:"namespace"`
		SimRate   Rate   `json:"sim_rate"`
		SysRate   Rate   `json:"sys_rate"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	cmd := &pb.ControllerCmd{
		CommandId: uuid.New().String(),
		Payload: &pb.ControllerCmd_ApplyPolicy{
			ApplyPolicy: &pb.ApplyPodPolicy{
				PodName:   req.PodName,
				Namespace: req.Namespace,
				SimRate: &pb.RateLimit{
					UploadBps:   req.SimRate.Upload,
					DownloadBps: req.SimRate.Download,
				},
				SysRate: &pb.RateLimit{
					UploadBps:   req.SysRate.Upload,
					DownloadBps: req.SysRate.Download,
				},
			},
		},
	}

	if err := c.sendCommandToNode(req.NodeName, cmd); err != nil {
		log.Printf("[API Error] ApplyPodPolicy: %v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	log.Printf("[API] Sent ApplyPodPolicy to %s (Pod: %s)", req.NodeName, req.PodName)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "sent", "command_id": "` + cmd.CommandId + `"}`))
}

func (c *ControllerManager) ApplyNodePolicyAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		NodeName          string `json:"node_name"`
		IngressLimitBps   uint64 `json:"ingress_limit_bps"`
		IngressBurstBytes uint64 `json:"ingress_burst_bytes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	cmd := &pb.ControllerCmd{
		CommandId: uuid.New().String(),
		Payload: &pb.ControllerCmd_ApplyNodePolicy{
			ApplyNodePolicy: &pb.ApplyNodePolicy{
				IngressLimitBps:   req.IngressLimitBps,
				IngressBurstBytes: req.IngressBurstBytes,
			},
		},
	}

	if err := c.sendCommandToNode(req.NodeName, cmd); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	log.Printf("[API] Sent ApplyNodePolicy to %s", req.NodeName)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "sent", "command_id": "` + cmd.CommandId + `"}`))
}

func (c *ControllerManager) SyncWhitelistAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		NodeName string   `json:"node_name"`
		IPs      []string `json:"ips"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	cmd := &pb.ControllerCmd{
		CommandId: uuid.New().String(),
		Payload: &pb.ControllerCmd_SyncPeers{
			SyncPeers: &pb.SyncPeerWhitelist{
				PeerIps: req.IPs,
			},
		},
	}

	if req.NodeName != "" {
		// Unicast to specific node
		if err := c.sendCommandToNode(req.NodeName, cmd); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	} else {
		// Broadcast to all connected agents
		var errs []string
		c.activeAgents.Range(func(key, value any) bool {
			node := key.(string)
			session := value.(*AgentSession)
			if err := session.SendSafe(cmd); err != nil {
				log.Printf("Failed to broadcast to %s: %v", node, err)
				errs = append(errs, node)
			}
			return true
		})
		if len(errs) > 0 {
			log.Printf("[API Warning] Broadcast failed for nodes: %v", errs)
		}
	}

	log.Printf("[API] Sent SyncWhitelist (%d IPs) to Node: %s (Empty=All)", len(req.IPs), req.NodeName)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "sent", "command_id": "` + cmd.CommandId + `"}`))
}
