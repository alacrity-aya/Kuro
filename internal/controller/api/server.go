package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"kuro/internal/controller"
	"kuro/internal/domain"
)

type HTTPServer struct {
	manager *controller.ControllerManager
	port    int
}

func NewHTTPServer(manager *controller.ControllerManager, port int) *HTTPServer {
	return &HTTPServer{
		manager: manager,
		port:    port,
	}
}

func (s *HTTPServer) Run() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/agents", s.ListAgentsAPI)
	mux.HandleFunc("/api/v1/policy/link", s.ApplyLinkPolicyAPI)
	mux.HandleFunc("/api/v1/policy/pod", s.ApplyPodPolicyAPI)
	mux.HandleFunc("/api/v1/policy/node", s.ApplyNodePolicyAPI)

	log.Printf("[API] HTTP Server listening on :%d", s.port)
	return http.ListenAndServe(fmt.Sprintf(":%d", s.port), mux)
}

// =============================================================
// Handlers
// =============================================================

func (s *HTTPServer) ListAgentsAPI(w http.ResponseWriter, r *http.Request) {
	agents := s.manager.ListAgents()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"count": len(agents),
		"nodes": agents,
	})
}

func (s *HTTPServer) ApplyLinkPolicyAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Define Request DTO (Can be local or defined in api/types.go)
	var req struct {
		NodeName          string `json:"node_name"`
		SrcIp             string `json:"src_ip"`
		DstIp             string `json:"dst_ip"`
		BandwidthLimit    uint64 `json:"bandwidth_limit"`
		BaseLatencyNs     uint64 `json:"base_latency_ns"`
		JitterNs          uint64 `json:"jitter_ns"`
		CorruptionRatePpm uint32 `json:"corruption_rate_ppm"`
		QueueDepthNs      uint64 `json:"queue_depth_ns"`
		IsDelete          bool   `json:"is_delete"` // Or determine based on whether policy fields exist
	}

	// For simplicity, assume the Client explicitly passes parameters
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Construct Domain Object
	policy := domain.LinkPolicy{
		SrcIP:             req.SrcIp,
		DstIP:             req.DstIp,
		BandwidthBps:      req.BandwidthLimit,
		BaseLatencyNs:     req.BaseLatencyNs,
		JitterNs:          req.JitterNs,
		CorruptionRatePpm: req.CorruptionRatePpm,
		QueueDepthNs:      req.QueueDepthNs,
		IsDelete:          req.IsDelete, // Client explicitly controls deletion
	}

	// Call Controller business logic
	cmdID, err := s.manager.SendCommand(req.NodeName, policy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	log.Printf("[API] Applied LinkPolicy on %s", req.NodeName)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status": "ok", "command_id": "%s"}`, cmdID)
}

// ApplyPodPolicyAPI configures interface-level limits (Sim/Sys rates) for a Pod.
func (s *HTTPServer) ApplyPodPolicyAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Define Request DTO
	type Rate struct {
		Upload   uint64 `json:"upload"`   // bps
		Download uint64 `json:"download"` // bps
	}

	var req struct {
		NodeName  string `json:"node_name"`
		PodName   string `json:"pod_name"`
		Namespace string `json:"namespace"`
		SimRate   *Rate  `json:"sim_rate"` // Simulation Network (Container Interface)
		SysRate   *Rate  `json:"sys_rate"` // System Network (Host Interface)
	}

	// 2. Decode JSON
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.NodeName == "" || req.PodName == "" {
		http.Error(w, "node_name and pod_name are required", http.StatusBadRequest)
		return
	}

	// 3. Build Domain Object
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

	// 4. Call Manager (SendCommand)
	cmdID, err := s.manager.SendCommand(req.NodeName, policy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// 5. Return Response
	log.Printf("[API] Applied Pod Policy for %s/%s on Node %s", req.Namespace, req.PodName, req.NodeName)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"status": "ok", "command_id": "%s"}`, cmdID)))
}

// ApplyNodePolicyAPI configures node-level ingress protection (XDP).
func (s *HTTPServer) ApplyNodePolicyAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Define Request DTO
	var req struct {
		NodeName          string `json:"node_name"`
		IngressLimitBps   uint64 `json:"ingress_limit_bps"`
		IngressBurstBytes uint64 `json:"ingress_burst_bytes"`
	}

	// 2. Decode JSON
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.NodeName == "" {
		http.Error(w, "node_name is required", http.StatusBadRequest)
		return
	}

	// 3. Build Domain Object
	policy := domain.NodePolicy{
		IngressLimitBps:   req.IngressLimitBps,
		IngressBurstBytes: req.IngressBurstBytes,
	}

	// 4. Call Manager (SendCommand)
	cmdID, err := s.manager.SendCommand(req.NodeName, policy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// 5. Return Response
	log.Printf("[API] Applied Node Policy on %s (Limit: %d bps)", req.NodeName, req.IngressLimitBps)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"status": "ok", "command_id": "%s"}`, cmdID)))
}
