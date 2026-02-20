package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"kuro/internal/domain"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type AgentManager interface {
	GetK8sClient() client.Client
	SendCommand(nodeName string, refKey string, payload any) (string, error)
	ListAgents() []string
}

type HTTPServer struct {
	manager AgentManager
	port    int
	server  *http.Server
}

func NewHTTPServer(manager AgentManager, port int) *HTTPServer {
	return &HTTPServer{
		manager: manager,
		port:    port,
	}
}

func (s *HTTPServer) Run() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/topology", s.handleGetTopology)
	mux.HandleFunc("/api/v1/agents", s.handleListAgents)
	mux.HandleFunc("/api/v1/policy/link", s.handleApplyLinkPolicy)
	mux.HandleFunc("/api/v1/policy/pod", s.handleApplyPodPolicy)
	mux.HandleFunc("/api/v1/policy/node", s.handleApplyNodePolicy)

	s.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.port),
		Handler: mux,
	}

	log.Printf("[API] HTTP Server listening on :%d", s.port)
	return s.server.ListenAndServe()
}

// =============================================================
// Handlers
// =============================================================

// 1. Get topology structure
func (s *HTTPServer) handleGetTopology(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	k8sClient := s.manager.GetK8sClient()
	if k8sClient == nil {
		http.Error(w, "K8s client not initialized", http.StatusServiceUnavailable)
		return
	}

	podList := &corev1.PodList{}
	opts := []client.ListOption{
		client.InNamespace("kuro-experiment"),
		client.MatchingLabels{"kuro.io/sim-node": "true"},
	}

	if err := k8sClient.List(r.Context(), podList, opts...); err != nil {
		log.Printf("[API] Failed to list pods in kuro-experiment: %v", err)
		http.Error(w, "Failed to fetch topology", http.StatusInternalServerError)
		return
	}

	response := domain.TopologyResponse{
		Nodes: make([]domain.TopologyNode, 0),
	}

	for _, pod := range podList.Items {
		groupName := pod.Labels["app"]
		if groupName == "" {
			groupName = "unknown"
		}

		node := domain.TopologyNode{
			Name:      pod.Name,
			Group:     groupName,
			Namespace: pod.Namespace,
			IP:        pod.Status.PodIP,
			Status:    string(pod.Status.Phase),
		}
		response.Nodes = append(response.Nodes, node)
	}

	s.jsonResponse(w, response)
}

func (s *HTTPServer) handleListAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	agents := s.manager.ListAgents()
	s.jsonResponse(w, map[string]any{
		"count": len(agents),
		"nodes": agents,
	})
}

func (s *HTTPServer) handleApplyLinkPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		NodeName          string `json:"node_name"`
		SrcIP             string `json:"src_ip"`
		DstIP             string `json:"dst_ip"`
		BandwidthLimit    uint64 `json:"bandwidth_limit"`
		BaseLatencyNs     uint64 `json:"base_latency_ns"`
		JitterNs          uint64 `json:"jitter_ns"`
		CorruptionRatePpm uint32 `json:"corruption_rate_ppm"`
		QueueDepthNs      uint64 `json:"queue_depth_ns"`
		IsDelete          bool   `json:"is_delete"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	policy := domain.LinkPolicy{
		SrcIP:             req.SrcIP,
		DstIP:             req.DstIP,
		BandwidthBps:      req.BandwidthLimit,
		BaseLatencyNs:     req.BaseLatencyNs,
		JitterNs:          req.JitterNs,
		CorruptionRatePpm: req.CorruptionRatePpm,
		QueueDepthNs:      req.QueueDepthNs,
		IsDelete:          req.IsDelete,
	}

	cmdID, err := s.manager.SendCommand(req.NodeName, "manual-api", policy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	log.Printf("[API] Applied LinkPolicy on %s", req.NodeName)
	s.jsonResponse(w, map[string]string{"status": "ok", "command_id": cmdID})
}

func (s *HTTPServer) handleApplyPodPolicy(w http.ResponseWriter, r *http.Request) {
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
		SimRate   *Rate  `json:"sim_rate"`
		SysRate   *Rate  `json:"sys_rate"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	policy := domain.PodPolicy{
		PodName:   req.PodName,
		Namespace: req.Namespace,
	}
	if req.SimRate != nil {
		policy.SimRate = &domain.RateLimit{
			UploadBps:   req.SimRate.Upload,
			DownloadBps: req.SimRate.Download,
		}
	}
	if req.SysRate != nil {
		policy.SysRate = &domain.RateLimit{
			UploadBps:   req.SysRate.Upload,
			DownloadBps: req.SysRate.Download,
		}
	}

	cmdID, err := s.manager.SendCommand(req.NodeName, "manual-api", policy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	s.jsonResponse(w, map[string]string{"status": "ok", "command_id": cmdID})
}

func (s *HTTPServer) handleApplyNodePolicy(w http.ResponseWriter, r *http.Request) {
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

	policy := domain.NodePolicy{
		IngressLimitBps:   req.IngressLimitBps,
		IngressBurstBytes: req.IngressBurstBytes,
	}

	cmdID, err := s.manager.SendCommand(req.NodeName, "manual-api", policy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	s.jsonResponse(w, map[string]string{"status": "ok", "command_id": cmdID})
}

func (s *HTTPServer) jsonResponse(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[API] Failed to encode response: %v", err)
	}
}
