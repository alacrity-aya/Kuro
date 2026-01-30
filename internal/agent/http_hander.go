package agent

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"strings"
)

func (a *Agent) startHTTPServer() {
	// 1. Debug API: List Pods
	http.HandleFunc("/debug/pods", func(w http.ResponseWriter, r *http.Request) {
		pods := a.localWatcher.GetAllPods()
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(pods); err != nil {
			log.Printf("[Agent] Failed to encode debug info: %v", err)
		}
	})

	// 2. Debug API: List Peers (Whitelist)
	http.HandleFunc("/debug/peers", func(w http.ResponseWriter, r *http.Request) {
		peers, err := a.bpfManager.GetPeers()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get peers: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(peers); err != nil {
			log.Printf("[Agent] Failed to encode peers info: %v", err)
		}
	})

	// 3. Ops API: Set Rate Limits
	// Usage:
	//   curl "http://localhost:8080/ops/limit?sim_up=10M&sim_down=20M&sys_up=1G&sys_down=1G"
	//   Note: Supports "sim_up", "sim_down", "sys_up", "sys_down" parameters. Values are in bytes/sec.
	http.HandleFunc("/ops/limit", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		// Helper to parse uint64
		parseParam := func(key string) uint64 {
			valStr := q.Get(key)
			if valStr == "" {
				return 0
			}
			var val uint64
			// Simple parsing, assumes raw bytes integer.
			// In production you might want to handle suffixes like '10M'
			fmt.Sscanf(valStr, "%d", &val)
			return val
		}

		simUp := parseParam("sim_up")
		simDown := parseParam("sim_down")
		sysUp := parseParam("sys_up")
		sysDown := parseParam("sys_down")

		log.Printf("[Agent API] Request: Set LIMIT -> Sim(UL:%d, DL:%d), Sys(UL:%d, DL:%d)",
			simUp, simDown, sysUp, sysDown)

		pods := a.localWatcher.GetAllPods()
		results := make(map[string]string)

		for _, p := range pods {
			if p.Info.HostIfIndex == 0 {
				results[p.Info.Name] = "Skipped (No HostIfIndex)"
				continue
			}

			podCtx, ok := a.localWatcher.GetPodContext(p.Info.Name)
			if !ok || !podCtx.NetnsHandle.IsOpen() {
				results[p.Info.Name] = "Skipped (Invalid Context)"
				continue
			}

			// Ensure BPF is attached
			if err := a.bpfManager.AddPod(p.Info.Name, p.Info.HostIfIndex, podCtx.NetnsHandle); err != nil {
				errMsg := fmt.Sprintf("Failed to attach BPF: %v", err)
				log.Printf("[Agent API] %s: %s", p.Info.Name, errMsg)
				results[p.Info.Name] = errMsg
				continue
			}

			// Update Rules (4 Parameters)
			if err := a.bpfManager.UpdateRule(p.Info.HostIfIndex, simUp, simDown, sysUp, sysDown); err != nil {
				errMsg := fmt.Sprintf("Failed to update rule: %v", err)
				log.Printf("[Agent API] %s: %s", p.Info.Name, errMsg)
				results[p.Info.Name] = errMsg
				continue
			}

			results[p.Info.Name] = "Success"
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(results)
	})

	// 4. Metrics API: Prometheus Format (New)
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		metrics, err := a.bpfManager.CollectAllMetrics()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to collect metrics: %v", err), http.StatusInternalServerError)
			return
		}

		var sb strings.Builder

		// Helper to write counter
		writeCounter := func(name, pod, direction, trafficType string, value uint64) {
			fmt.Fprintf(&sb, "%s{pod=\"%s\",direction=\"%s\",type=\"%s\"} %d\n",
				name, pod, direction, trafficType, value)
		}

		// Write Header
		sb.WriteString("# HELP kuro_pod_traffic_bytes_total Total bytes passed through the simulation filter\n")
		sb.WriteString("# TYPE kuro_pod_traffic_bytes_total counter\n")
		sb.WriteString("# HELP kuro_pod_traffic_packets_total Total packets passed through the simulation filter\n")
		sb.WriteString("# TYPE kuro_pod_traffic_packets_total counter\n")
		sb.WriteString("# HELP kuro_pod_drop_bytes_total Total bytes dropped by rate limiting\n")
		sb.WriteString("# TYPE kuro_pod_drop_bytes_total counter\n")
		sb.WriteString("# HELP kuro_pod_drop_packets_total Total packets dropped by rate limiting\n")
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
		sb.WriteString("# HELP kuro_pod_latency_seconds Latency added by the shaper (microseconds precision)\n")
		sb.WriteString("# TYPE kuro_pod_latency_seconds histogram\n")

		for _, m := range metrics {
			var cumulative uint64 = 0
			// 16 buckets from tc.c
			for i := range 16 {
				count := m.Latency.Buckets[i]
				cumulative += count
				// Bucket i corresponds to log2(us).
				// Upper bound of bucket i is roughly 2^(i+1) microseconds.
				// Convert to seconds for Prometheus convention.
				le := math.Pow(2, float64(i+1)) / 1e6
				fmt.Fprintf(&sb, "kuro_pod_latency_seconds_bucket{pod=\"%s\",le=\"%f\"} %d\n", m.PodName, le, cumulative)
			}
			fmt.Fprintf(&sb, "kuro_pod_latency_seconds_bucket{pod=\"%s\",le=\"+Inf\"} %d\n", m.PodName, cumulative)
			fmt.Fprintf(&sb, "kuro_pod_latency_seconds_count{pod=\"%s\"} %d\n", m.PodName, cumulative)
			// Sum is missing in our eBPF histogram, but Count/Bucket is enough for heatmap
		}

		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.Write([]byte(sb.String()))
	})

	log.Println("[Agent] Debug server listening on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Printf("[Agent] Debug server error: %v", err)
	}
}
