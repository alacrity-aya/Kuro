package opsapi

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"strings"

	"kuro/internal/agent/bpf"
	"kuro/internal/agent/probe"
	"kuro/internal/agent/watch"
)

// HTTPService handles HTTP requests related to operations and debugging
type HTTPService struct {
	localWatcher *watch.LocalWatcher
	bpfManager   *bpf.BpfManager
	probeMetrics *probe.MetricsStore
}

// NewHTTPService initializes HTTP service dependencies
func NewHTTPService(watcher *watch.LocalWatcher, bpfMgr *bpf.BpfManager, probeMetrics *probe.MetricsStore) *HTTPService {
	return &HTTPService{
		localWatcher: watcher,
		bpfManager:   bpfMgr,
		probeMetrics: probeMetrics,
	}
}

// Start begins HTTP listening
func (s *HTTPService) Start(port int) {
	mux := http.NewServeMux()

	// === Core Operations APIs ===
	// 1. System Dashboard: Provides an aggregated view of all Pods (traffic, limits, active policies, last activity time)
	mux.HandleFunc("/ops/dashboard", s.handleDashboard)
	// 2. Rate Limit Control: Dynamically adjusts Sim/Sys upload and download bandwidth
	mux.HandleFunc("/ops/limit", s.handleOpsLimit)

	// === Monitoring API ===
	// Prometheus format metrics exporter
	mux.HandleFunc("/metrics", s.handleMetrics)

	// === Low-level Debugging APIs (Human Readable) ===
	mux.HandleFunc("/debug/pods", s.handleDebugPods)                // Pod info from the K8s/LocalWatcher perspective
	mux.HandleFunc("/debug/bpf/rates", s.handleDebugBpfRates)       // Current bandwidth configuration (Mbps)
	mux.HandleFunc("/debug/bpf/state", s.handleDebugBpfState)       // EDT scheduler internal state (time delta)
	mux.HandleFunc("/debug/bpf/policies", s.handleDebugBpfPolicies) // Peer-to-peer policy details
	mux.HandleFunc("/debug/bpf/ingress", s.handleDebugBpfIngress)   // Physical NIC ingress protection status

	addr := fmt.Sprintf(":%d", port)
	log.Printf("[OpsAPI] Listening on %s (Try /ops/dashboard)", addr)

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Printf("[OpsAPI] Server error: %v", err)
	}
}

// handleDashboard provides a global aggregated view of the system
func (s *HTTPService) handleDashboard(w http.ResponseWriter, r *http.Request) {
	// Call BpfManager's aggregation method to retrieve data
	overview, err := s.bpfManager.GetSystemDashboard()
	if err != nil {
		s.jsonError(w, fmt.Sprintf("Failed to generate dashboard: %v", err))
		return
	}

	ingressInfo, _ := s.bpfManager.DumpIngress()

	response := map[string]any{
		"system_status":      "running",
		"managed_pods_count": len(overview),
		"ingress_protection": ingressInfo,
		"pods":               overview,
	}

	s.jsonResponse(w, response)
}

// handleOpsLimit handles bandwidth limit requests
// Parameters: ?sim_up=X&sim_down=Y&sys_up=Z&sys_down=W (unit: bps)
func (s *HTTPService) handleOpsLimit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// Helper parsing function
	parseParam := func(key string) uint64 {
		valStr := q.Get(key)
		if valStr == "" {
			return 0
		}
		var val uint64
		// Error tolerance handling
		if _, err := fmt.Sscanf(valStr, "%d", &val); err != nil {
			return 0
		}
		return val
	}

	simUp := parseParam("sim_up")
	simDown := parseParam("sim_down")
	sysUp := parseParam("sys_up")
	sysDown := parseParam("sys_down")

	log.Printf("[OpsAPI] LIMIT REQ: Sim(UL:%d, DL:%d), Sys(UL:%d, DL:%d)", simUp, simDown, sysUp, sysDown)

	pods := s.localWatcher.GetAllPods()
	results := make(map[string]string)

	for _, p := range pods {
		if p.Info.HostIfIndex == 0 {
			continue
		}

		// Validate Pod context and Netns validity
		podCtx, ok := s.localWatcher.GetPodContext(p.Info.Name)
		if !ok || !podCtx.NetnsHandle.IsOpen() {
			results[p.Info.Name] = "Skipped (Invalid Context/Closed Netns)"
			continue
		}

		// 1. Ensure BPF programs are attached (idempotent operation)
		if err := s.bpfManager.AddPod(p.Info.Name, p.Info.HostIfIndex, podCtx.NetnsHandle); err != nil {
			errMsg := fmt.Sprintf("Failed to attach BPF: %v", err)
			log.Printf("[OpsAPI] Error %s: %s", p.Info.Name, errMsg)
			results[p.Info.Name] = errMsg
			continue
		}

		// 2. Update bandwidth rules
		if err := s.bpfManager.UpdateRule(p.Info.HostIfIndex, simUp, simDown, sysUp, sysDown); err != nil {
			errMsg := fmt.Sprintf("Failed to update rule: %v", err)
			log.Printf("[OpsAPI] Error %s: %s", p.Info.Name, errMsg)
			results[p.Info.Name] = errMsg
			continue
		}

		results[p.Info.Name] = "Success"
	}

	s.jsonResponse(w, results)
}

// handleMetrics exports metrics in Prometheus format
func (s *HTTPService) handleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics, err := s.bpfManager.CollectAllMetrics()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to collect metrics: %v", err), http.StatusInternalServerError)
		return
	}

	var sb strings.Builder

	// Helper write function
	writeCounter := func(name, pod, direction, trafficType string, value uint64) {
		fmt.Fprintf(&sb, "%s{pod=\"%s\",direction=\"%s\",type=\"%s\"} %d\n",
			name, pod, direction, trafficType, value)
	}

	// Write metric header information
	sb.WriteString("# HELP kuro_pod_traffic_bytes_total Total bytes passed\n")
	sb.WriteString("# TYPE kuro_pod_traffic_bytes_total counter\n")
	sb.WriteString("# HELP kuro_pod_traffic_packets_total Total packets passed\n")
	sb.WriteString("# TYPE kuro_pod_traffic_packets_total counter\n")
	sb.WriteString("# HELP kuro_pod_drop_bytes_total Total bytes dropped\n")
	sb.WriteString("# TYPE kuro_pod_drop_bytes_total counter\n")
	sb.WriteString("# HELP kuro_pod_drop_packets_total Total packets dropped\n")
	sb.WriteString("# TYPE kuro_pod_drop_packets_total counter\n")

	for _, m := range metrics {
		// Sim Download
		writeCounter("kuro_pod_traffic_bytes_total", m.PodName, "download", "sim", m.Stats.SimDownload.Bytes)
		writeCounter("kuro_pod_traffic_packets_total", m.PodName, "download", "sim", m.Stats.SimDownload.Packets)
		writeCounter("kuro_pod_drop_bytes_total", m.PodName, "download", "sim", m.Stats.SimDownload.DropBytes)
		writeCounter("kuro_pod_drop_packets_total", m.PodName, "download", "sim", m.Stats.SimDownload.DropPackets)

		// Sim Upload
		writeCounter("kuro_pod_traffic_bytes_total", m.PodName, "upload", "sim", m.Stats.SimUpload.Bytes)
		writeCounter("kuro_pod_traffic_packets_total", m.PodName, "upload", "sim", m.Stats.SimUpload.Packets)
		writeCounter("kuro_pod_drop_bytes_total", m.PodName, "upload", "sim", m.Stats.SimUpload.DropBytes)
		writeCounter("kuro_pod_drop_packets_total", m.PodName, "upload", "sim", m.Stats.SimUpload.DropPackets)

		// Sys Download
		writeCounter("kuro_pod_traffic_bytes_total", m.PodName, "download", "sys", m.Stats.SysDownload.Bytes)
		writeCounter("kuro_pod_traffic_packets_total", m.PodName, "download", "sys", m.Stats.SysDownload.Packets)
		writeCounter("kuro_pod_drop_bytes_total", m.PodName, "download", "sys", m.Stats.SysDownload.DropBytes)
		writeCounter("kuro_pod_drop_packets_total", m.PodName, "download", "sys", m.Stats.SysDownload.DropPackets)

		// Sys Upload
		writeCounter("kuro_pod_traffic_bytes_total", m.PodName, "upload", "sys", m.Stats.SysUpload.Bytes)
		writeCounter("kuro_pod_traffic_packets_total", m.PodName, "upload", "sys", m.Stats.SysUpload.Packets)
		writeCounter("kuro_pod_drop_bytes_total", m.PodName, "upload", "sys", m.Stats.SysUpload.DropBytes)
		writeCounter("kuro_pod_drop_packets_total", m.PodName, "upload", "sys", m.Stats.SysUpload.DropPackets)
	}

	// Latency Histogram
	sb.WriteString("# HELP kuro_pod_latency_seconds Latency added by the shaper\n")
	sb.WriteString("# TYPE kuro_pod_latency_seconds histogram\n")

	for _, m := range metrics {
		var cumulative uint64 = 0
		// 16 buckets based on tc.c / manager.go logic
		for i := range 16 {
			count := m.Latency.Buckets[i]
			cumulative += count
			// Scale to seconds for Prometheus convention (microseconds -> seconds)
			// Bucket 0 = 2^1 us, Bucket 1 = 2^2 us, ...
			le := math.Pow(2, float64(i+1)) / 1e6
			fmt.Fprintf(&sb, "kuro_pod_latency_seconds_bucket{pod=\"%s\",le=\"%f\"} %d\n", m.PodName, le, cumulative)
		}
		fmt.Fprintf(&sb, "kuro_pod_latency_seconds_bucket{pod=\"%s\",le=\"+Inf\"} %d\n", m.PodName, cumulative)
		fmt.Fprintf(&sb, "kuro_pod_latency_seconds_count{pod=\"%s\"} %d\n", m.PodName, cumulative)
	}


	// Probe RTT Metrics
	if s.probeMetrics != nil {
		s.probeMetrics.WritePrometheus(&sb)
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.Write([]byte(sb.String()))
}

// === Debug Handlers (Using Human Readable methods) ===

func (s *HTTPService) handleDebugPods(w http.ResponseWriter, r *http.Request) {
	pods := s.localWatcher.GetAllPods()
	s.jsonResponse(w, pods)
}

func (s *HTTPService) handleDebugBpfRates(w http.ResponseWriter, r *http.Request) {
	// Use DumpRateMapHuman to get readable Mbps data
	info, err := s.bpfManager.DumpRateMapHuman()
	if err != nil {
		s.jsonError(w, fmt.Sprintf("Error dumping rate map: %v", err))
		return
	}
	s.jsonResponse(w, info)
}

func (s *HTTPService) handleDebugBpfState(w http.ResponseWriter, r *http.Request) {
	// Use DumpEdtStateHuman to get readable time difference data
	info, err := s.bpfManager.DumpEdtStateHuman()
	if err != nil {
		s.jsonError(w, fmt.Sprintf("Error dumping edt state: %v", err))
		return
	}
	s.jsonResponse(w, info)
}

func (s *HTTPService) handleDebugBpfPolicies(w http.ResponseWriter, r *http.Request) {
	// Use DumpPoliciesHuman to get readable latency and loss rate data
	info, err := s.bpfManager.DumpPoliciesHuman()
	if err != nil {
		s.jsonError(w, fmt.Sprintf("Error dumping policies: %v", err))
		return
	}
	s.jsonResponse(w, info)
}

func (s *HTTPService) handleDebugBpfIngress(w http.ResponseWriter, r *http.Request) {
	info, err := s.bpfManager.DumpIngress()
	if err != nil {
		s.jsonError(w, fmt.Sprintf("Error dumping ingress: %v", err))
		return
	}
	s.jsonResponse(w, info)
}

// === General Utility Functions ===

func (s *HTTPService) jsonResponse(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ") // Formatted output for easier curl debugging
	if err := encoder.Encode(data); err != nil {
		log.Printf("[OpsAPI] Failed to encode response: %v", err)
	}
}

func (s *HTTPService) jsonError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	// Ignore error handling to avoid infinite loops
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": msg,
	})
}
