package probe

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"kuro/internal/domain"
)

// histBuckets defines bucket upper bounds in seconds for the RTT histogram.
// Buckets: 100us, 500us, 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, 100ms, 200ms, 500ms, 1s, 2s, 5s
var histBuckets = []float64{
	0.0001, 0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0,
}

// probeResult holds aggregated metrics for a single probe task.
type probeResult struct {
	SrcPod  string
	DstPod  string
	Type    string // "sim" or "sys"
	LastRTT float64
	Success bool

	// Histogram data
	BucketCounts [14]uint64 // One per histBuckets entry
	TotalCount   uint64
	TotalSum     float64
}

// MetricsStore is a thread-safe store for probe RTT results.
type MetricsStore struct {
	mu      sync.RWMutex
	results map[string]*probeResult // taskID -> result
}

func NewMetricsStore() *MetricsStore {
	return &MetricsStore{
		results: make(map[string]*probeResult),
	}
}

// RecordResult records a probe result for a task.
func (s *MetricsStore) RecordResult(task domain.ProbeTask, rtt time.Duration, success bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r, exists := s.results[task.TaskID]
	if !exists {
		r = &probeResult{
			SrcPod: task.SrcPod,
			DstPod: task.DstPod,
			Type:   task.Type.String(),
		}
		s.results[task.TaskID] = r
	}

	r.Success = success

	if success {
		rttSec := rtt.Seconds()
		r.LastRTT = rttSec
		r.TotalCount++
		r.TotalSum += rttSec

		// Update histogram buckets
		for i, bound := range histBuckets {
			if rttSec <= bound {
				r.BucketCounts[i]++
				break
			}
			// If larger than all buckets, count in the last bucket
			if i == len(histBuckets)-1 {
				r.BucketCounts[i]++
			}
		}
	}
}

// RemoveTask removes metrics for a specific task.
func (s *MetricsStore) RemoveTask(taskID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.results, taskID)
}

// WritePrometheus writes all probe metrics in Prometheus text exposition format.
// This follows the exact pattern from opsapi/http_service.go (manual text format).
func (s *MetricsStore) WritePrometheus(sb *strings.Builder) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.results) == 0 {
		return
	}

	// Gauge: current RTT
	sb.WriteString("# HELP kuro_probe_rtt_seconds Current RTT measured by TCP probe\n")
	sb.WriteString("# TYPE kuro_probe_rtt_seconds gauge\n")
	for _, r := range s.results {
		if r.Success {
			fmt.Fprintf(sb, "kuro_probe_rtt_seconds{src_pod=\"%s\",dst_pod=\"%s\",type=\"%s\"} %f\n",
				r.SrcPod, r.DstPod, r.Type, r.LastRTT)
		}
	}

	// Gauge: probe success (1 = success, 0 = failure)
	sb.WriteString("# HELP kuro_probe_success Whether the last probe was successful\n")
	sb.WriteString("# TYPE kuro_probe_success gauge\n")
	for _, r := range s.results {
		val := 0
		if r.Success {
			val = 1
		}
		fmt.Fprintf(sb, "kuro_probe_success{src_pod=\"%s\",dst_pod=\"%s\",type=\"%s\"} %d\n",
			r.SrcPod, r.DstPod, r.Type, val)
	}

	// Histogram: RTT distribution
	sb.WriteString("# HELP kuro_probe_rtt_histogram_seconds RTT histogram measured by TCP probe\n")
	sb.WriteString("# TYPE kuro_probe_rtt_histogram_seconds histogram\n")
	for _, r := range s.results {
		var cumulative uint64
		for i, bound := range histBuckets {
			cumulative += r.BucketCounts[i]
			le := bound
			fmt.Fprintf(sb, "kuro_probe_rtt_histogram_seconds_bucket{src_pod=\"%s\",dst_pod=\"%s\",type=\"%s\",le=\"%s\"} %d\n",
				r.SrcPod, r.DstPod, r.Type, formatFloat(le), cumulative)
		}
		fmt.Fprintf(sb, "kuro_probe_rtt_histogram_seconds_bucket{src_pod=\"%s\",dst_pod=\"%s\",type=\"%s\",le=\"+Inf\"} %d\n",
			r.SrcPod, r.DstPod, r.Type, cumulative)
		fmt.Fprintf(sb, "kuro_probe_rtt_histogram_seconds_sum{src_pod=\"%s\",dst_pod=\"%s\",type=\"%s\"} %f\n",
			r.SrcPod, r.DstPod, r.Type, r.TotalSum)
		fmt.Fprintf(sb, "kuro_probe_rtt_histogram_seconds_count{src_pod=\"%s\",dst_pod=\"%s\",type=\"%s\"} %d\n",
			r.SrcPod, r.DstPod, r.Type, r.TotalCount)
	}
}

// formatFloat formats a float without trailing zeros for cleaner Prometheus output.
func formatFloat(f float64) string {
	if f == math.Trunc(f) {
		return fmt.Sprintf("%.1f", f)
	}
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", f), "0"), ".")
}
