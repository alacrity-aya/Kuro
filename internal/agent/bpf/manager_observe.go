package bpf

import (
	"fmt"
	"time"

	"github.com/cilium/ebpf"
)

// ======================================================================================
// Human-Readable Structures (Used for enhanced observability)
// ======================================================================================

// HumanRateInfo provides raw BPF cost values and converted Mbps strings
type HumanRateInfo struct {
	PodName        string   `json:"pod_name"`
	IfIndex        uint32   `json:"if_index"`
	Side           string   `json:"side"` // "Host" or "Pod"
	SimDownRateStr string   `json:"sim_down_rate"`
	SysDownRateStr string   `json:"sys_down_rate"`
	SimUpRateStr   string   `json:"sim_up_rate"`
	SysUpRateStr   string   `json:"sys_up_rate"`
	Raw            TcIoRate `json:"raw_config"`
}

type HumanEdtState struct {
	PodName      string `json:"pod_name"`
	Direction    string `json:"direction"`
	TrafficType  string `json:"type"`
	LastPacket   string `json:"last_packet_seen"` // e.g., "150ms ago"
	IdleDuration string `json:"idle_duration"`
	IsActive     bool   `json:"is_active"` // True if seen in last 5 seconds
}

type HumanPolicy struct {
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	Bandwidth string `json:"bandwidth_limit"` // e.g., "50 Mbps" or "Unlimited"
	Latency   string `json:"latency"`         // e.g., "20ms"
	Jitter    string `json:"jitter"`
	Loss      string `json:"loss_rate"` // e.g., "0.5%"
}

// SystemOverview aggregates all views for a single Pod
type SystemOverview struct {
	PodName      string        `json:"pod_name"`
	HostIfIndex  int           `json:"host_ifindex"`
	IP           string        `json:"pod_ip"`
	DownloadRate string        `json:"download_limit_sim"`
	UploadRate   string        `json:"upload_limit_sim"`
	TotalBytes   uint64        `json:"total_bytes_moved"`
	ActiveLinks  []HumanPolicy `json:"active_policies"`
	LastSeen     string        `json:"last_activity"`
}

// PodMetricsResult used for final metrics output
type PodMetricsResult struct {
	PodName     string        `json:"pod_name"`
	HostIfIndex int           `json:"host_ifindex"`
	Timestamp   int64         `json:"timestamp"`
	Stats       TcPodStats    `json:"stats"`
	Latency     TcLatencyHist `json:"latency"`
}

// ======================================================================================
// Observation Methods (Observability/Read Logic)
// ======================================================================================

// DumpIngress exports the protection state of the physical NIC ingress
func (m *BpfManager) DumpIngress() (map[string]any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := uint32(0)
	var cfg TcIngressConfig
	var state TcIngressState

	res := make(map[string]any)

	if err := m.objects.IngressConfigMap.Lookup(&key, &cfg); err == nil {
		res["config_cost_per_byte"] = cfg.CostPerByteNsScaled
		res["config_burst_ns"] = cfg.BurstNs
		// Add human-readable conversion
		res["human_limit"] = costToMbpsStr(cfg.CostPerByteNsScaled)
	}

	if err := m.objects.IngressStateMap.Lookup(&key, &state); err == nil {
		res["state_tokens_ns"] = state.TokensNs
		res["state_last_updated"] = state.LastUpdated
	}

	return res, nil
}

// DumpRateMapHuman exports current bandwidth limits in Mbps string format
func (m *BpfManager) DumpRateMapHuman() ([]HumanRateInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var results []HumanRateInfo
	var key uint32
	var val TcIoRate

	iter := m.objects.RateMap.Iterate()
	for iter.Next(&key, &val) {
		podName, side := m.resolvePodNameAndSide(key)

		// Filter empty entries
		if val.CostPerByteSimDownload == 0 && val.CostPerByteSysDownload == 0 &&
			val.CostPerByteSimUpload == 0 && val.CostPerByteSysUpload == 0 {
			continue
		}

		results = append(results, HumanRateInfo{
			PodName:        podName,
			IfIndex:        key,
			Side:           side,
			SimDownRateStr: costToMbpsStr(val.CostPerByteSimDownload),
			SysDownRateStr: costToMbpsStr(val.CostPerByteSysDownload),
			SimUpRateStr:   costToMbpsStr(val.CostPerByteSimUpload),
			SysUpRateStr:   costToMbpsStr(val.CostPerByteSysUpload),
			Raw:            val,
		})
	}
	return results, iter.Err()
}

// DumpEdtStateHuman exports scheduler state with relative time (e.g., "2s ago")
func (m *BpfManager) DumpEdtStateHuman() ([]HumanEdtState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var results []HumanEdtState

	// Get current kernel monotonic time for comparison
	nowNs, _ := getMonotonicTimeNs()

	processMap := func(mMap *ebpf.Map, direction string) {
		var key uint32
		var val TcEdtState
		iter := mMap.Iterate()
		for iter.Next(&key, &val) {
			ifIndex := key / 2
			typeIdx := key % 2

			// Resolve Pod Name
			podName := "Unknown"
			if prog, ok := m.programs[int(ifIndex)]; ok {
				podName = prog.podName
			} else {
				// Reverse lookup for Upload side
				for _, p := range m.programs {
					if p.podIfIndex == int(ifIndex) {
						podName = p.podName
						break
					}
				}
			}

			if val.T_last == 0 {
				continue
			}

			diffNs := int64(nowNs) - int64(val.T_last)
			if diffNs < 0 {
				diffNs = 0
			} // Clock skew protection

			typeName := "Sys"
			if typeIdx == 1 {
				typeName = "Sim"
			}

			results = append(results, HumanEdtState{
				PodName:      podName,
				Direction:    direction,
				TrafficType:  typeName,
				LastPacket:   fmt.Sprintf("%v ago", time.Duration(diffNs)),
				IdleDuration: time.Duration(diffNs).String(),
				IsActive:     diffNs < int64(5*time.Second), // Considered active if activity within 5s
			})
		}
	}

	processMap(m.objects.EdtDownloadStateMap, "Download")
	processMap(m.objects.EdtUploadStateMap, "Upload")

	return results, nil
}

// DumpPoliciesHuman exports policies with decoded units
func (m *BpfManager) DumpPoliciesHuman() ([]HumanPolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var results []HumanPolicy
	var key TcPolicyKey
	var val TcLinkPolicy

	iter := m.objects.TopologyPolicyMap.Iterate()
	for iter.Next(&key, &val) {
		srcIP := intToIP(key.SrcIp).String()
		dstIP := intToIP(key.DstIp).String()

		bw := "Unlimited"
		if val.CostPerByteScaled > 0 {
			bw = costToMbpsStr(val.CostPerByteScaled)
		}

		loss := "0%"
		if val.CorruptionThreshold > 0 {
			// Threshold = (ppm / 1,000,000) * UINT32_MAX
			// Reverse: ppm = (Threshold * 1,000,000) / UINT32_MAX
			ppm := (uint64(val.CorruptionThreshold) * 1_000_000) / 4294967295
			loss = fmt.Sprintf("%.4f%%", float64(ppm)/10000.0)
		}

		results = append(results, HumanPolicy{
			SrcIP:     srcIP,
			DstIP:     dstIP,
			Bandwidth: bw,
			Latency:   fmt.Sprintf("%dms", val.BaseLatencyNs/1_000_000),
			Jitter:    fmt.Sprintf("%dms", val.JitterNs/1_000_000),
			Loss:      loss,
		})
	}
	return results, iter.Err()
}

// GetSystemDashboard returns a high-level aggregated view of all managed Pods
func (m *BpfManager) GetSystemDashboard() ([]SystemOverview, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var overview []SystemOverview
	nowNs, _ := getMonotonicTimeNs()

	for ifIndex, prog := range m.programs {
		// 1. Get rates
		var rate TcIoRate
		key := uint32(ifIndex)
		_ = m.objects.RateMap.Lookup(&key, &rate) // Ignore error, defaults to zero-value

		// 2. Get metrics
		var stats []TcPodStats
		var totalBytes uint64
		if err := m.objects.MetricsMap.Lookup(&key, &stats); err == nil {
			for _, cpu := range stats {
				totalBytes += cpu.SimDownload.Bytes + cpu.SimUpload.Bytes + cpu.SysDownload.Bytes + cpu.SysUpload.Bytes
			}
		}

		// 3. Get last activity time (Check Download status)
		lastSeenStr := "Never"
		keySys := uint32(ifIndex * 2)
		keySim := uint32(ifIndex*2 + 1)
		var s1, s2 TcEdtState
		_ = m.objects.EdtDownloadStateMap.Lookup(&keySys, &s1)
		_ = m.objects.EdtDownloadStateMap.Lookup(&keySim, &s2)

		lastT := max(s2.T_last, s1.T_last)

		if lastT > 0 {
			diff := int64(nowNs) - int64(lastT)
			if diff >= 0 {
				lastSeenStr = fmt.Sprintf("%v ago", time.Duration(diff).Round(time.Second))
			}
		}

		// 4. Get active policies
		var policies []HumanPolicy
		for dstIP, cfg := range prog.activePolicies {
			policies = append(policies, HumanPolicy{
				SrcIP:     prog.podIP,
				DstIP:     dstIP,
				Bandwidth: fmt.Sprintf("%d Mbps", cfg.BandwidthLimit/1_000_000),
				Latency:   fmt.Sprintf("%d ms", cfg.BaseLatencyNs/1_000_000),
			})
		}

		overview = append(overview, SystemOverview{
			PodName:      prog.podName,
			HostIfIndex:  ifIndex,
			IP:           prog.podIP,
			DownloadRate: costToMbpsStr(rate.CostPerByteSimDownload),
			UploadRate:   costToMbpsStr(rate.CostPerByteSimUpload),
			TotalBytes:   totalBytes,
			ActiveLinks:  policies,
			LastSeen:     lastSeenStr,
		})
	}

	return overview, nil
}

// CollectAllMetrics collects statistics for all Pods (for Prometheus)
// Note: BPF stores metrics with different keys:
//   - Download direction (handle_edt_download): uses hostIfIndex as key
//   - Upload direction (handle_edt_upload): uses podIfIndex as key
// So we need to read from both and merge them.
func (m *BpfManager) CollectAllMetrics() ([]PodMetricsResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var results []PodMetricsResult

	for ifIndex, prog := range m.programs {
		hostKey := uint32(ifIndex)
		podKey := uint32(prog.podIfIndex)

		var totalStats TcPodStats

		// 1. Collect Download Stats (from hostIfIndex key)
		var hostStatsPerCPU []TcPodStats
		if err := m.objects.MetricsMap.Lookup(&hostKey, &hostStatsPerCPU); err == nil {
			for _, cpuStat := range hostStatsPerCPU {
				// Download metrics are stored with hostIfIndex
				totalStats.SimDownload.Packets += cpuStat.SimDownload.Packets
				totalStats.SimDownload.Bytes += cpuStat.SimDownload.Bytes
				totalStats.SimDownload.DropPackets += cpuStat.SimDownload.DropPackets
				totalStats.SimDownload.DropBytes += cpuStat.SimDownload.DropBytes
				totalStats.SysDownload.Packets += cpuStat.SysDownload.Packets
				totalStats.SysDownload.Bytes += cpuStat.SysDownload.Bytes
				totalStats.SysDownload.DropPackets += cpuStat.SysDownload.DropPackets
				totalStats.SysDownload.DropBytes += cpuStat.SysDownload.DropBytes
			}
		}

		// 2. Collect Upload Stats (from podIfIndex key) - CRITICAL FIX
		var podStatsPerCPU []TcPodStats
		if err := m.objects.MetricsMap.Lookup(&podKey, &podStatsPerCPU); err == nil {
			for _, cpuStat := range podStatsPerCPU {
				// Upload metrics are stored with podIfIndex
				totalStats.SimUpload.Packets += cpuStat.SimUpload.Packets
				totalStats.SimUpload.Bytes += cpuStat.SimUpload.Bytes
				totalStats.SimUpload.DropPackets += cpuStat.SimUpload.DropPackets
				totalStats.SimUpload.DropBytes += cpuStat.SimUpload.DropBytes
				totalStats.SysUpload.Packets += cpuStat.SysUpload.Packets
				totalStats.SysUpload.Bytes += cpuStat.SysUpload.Bytes
				totalStats.SysUpload.DropPackets += cpuStat.SysUpload.DropPackets
				totalStats.SysUpload.DropBytes += cpuStat.SysUpload.DropBytes
			}
		}

		// 3. Collect Latency Histogram (from both keys)
		var totalLatency TcLatencyHist
		var latHists []TcLatencyHist
		if err := m.objects.LatencyMap.Lookup(&hostKey, &latHists); err == nil {
			for _, h := range latHists {
				for i := range 16 {
					totalLatency.Buckets[i] += h.Buckets[i]
				}
			}
		}
		if err := m.objects.LatencyMap.Lookup(&podKey, &latHists); err == nil {
			for _, h := range latHists {
				for i := range 16 {
					totalLatency.Buckets[i] += h.Buckets[i]
				}
			}
		}

		results = append(results, PodMetricsResult{
			PodName:     prog.podName,
			HostIfIndex: ifIndex,
			Timestamp:   time.Now().UnixNano(),
			Stats:       totalStats,
			Latency:     totalLatency,
		})
	}

	return results, nil
}

// ================= Helpers =================
