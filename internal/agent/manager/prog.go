package manager

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"time"

	"github.com/alacrity-aya/Kuro/internal/bpf"
	"github.com/alacrity-aya/Kuro/internal/spec"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type BpfProgram struct {
	podName string

	links []link.Link
	objs  *bpf.TcObjects

	loaded bool

	ifaceIndex uint32

	lastCheckTime time.Time
	lastBytes     uint64
	smoothRate    float64
}

// apply initialze BpfProgram and update rule
func (p *BpfProgram) apply(sp spec.Spec) error {
	p.ifaceIndex = uint32(sp.IfaceIndex)
	p.podName = sp.PodName

	// load object
	if !p.loaded {
		p.objs = &bpf.TcObjects{}
		if err := bpf.LoadTcObjects(p.objs, nil); err != nil {
			return fmt.Errorf("failed to load ebpf objects: %w", err)
		}
		p.loaded = true
	}

	trafficRule := bpf.TcTrafficRule{
		RateBytes:  sp.RateLimit.RateBytes,
		BurstBytes: sp.RateLimit.BurstBytes,
	}

	if err := p.objs.TrafficRuleMap.Put(p.ifaceIndex, trafficRule); err != nil {
		return fmt.Errorf("failed to update traffic rule map: %w", err)
	}

	lossThreshold := uint32(0)
	if sp.Netem.LossPercent > 0 {
		// 0-100% -> 0-UINT32_MAX
		lossThreshold = uint32((sp.Netem.LossPercent / 100.0) * math.MaxUint32)
	}

	netemRule := bpf.TcNetemRule{
		DelayMs:       uint64(sp.Netem.LatencyMs),
		JitterMs:      uint64(sp.Netem.JitterMs),
		LossThreshold: lossThreshold,
	}

	if err := p.objs.NetemRuleMap.Put(p.ifaceIndex, netemRule); err != nil {
		return fmt.Errorf("failed to update netem rule map: %w", err)
	}

	if len(p.links) == 0 {

		l, err := link.AttachTCX(link.TCXOptions{
			Program:   p.objs.Gress,
			Interface: int(p.ifaceIndex),
			Attach:    ebpf.AttachTCXIngress,
		})
		if err != nil {
			return fmt.Errorf("failed to attach tc ingress: %w", err)
		}
		p.links = append(p.links, l)

	}

	return nil
}

func (p *BpfProgram) cleanUp() error {
	if !p.loaded {
		return nil
	}

	var errs []error

	// close links
	for _, l := range p.links {
		if err := l.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	p.links = nil

	// delete map entries
	if p.objs != nil {
		key := p.ifaceIndex
		_ = p.objs.TrafficRuleMap.Delete(key)
		_ = p.objs.NetemRuleMap.Delete(key)
		_ = p.objs.BucketStateMap.Delete(key)
		_ = p.objs.FlowCounterMap.Delete(key)

		// close fd
		if err := p.objs.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	p.objs = nil
	p.loaded = false

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %v", errs)
	}
	return nil
}

func (p *BpfProgram) getStats() TrafficStats {
	stats := TrafficStats{
		PodName: p.podName,
	}

	if !p.loaded || p.objs == nil {
		return stats
	}

	var counter bpf.TcFlowCounter
	if err := p.objs.FlowCounterMap.Lookup(p.ifaceIndex, &counter); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Error("failed to lookup flow stats", "err", err)
		}
		return stats
	}

	stats.TotalAcceptedBytes = counter.AcceptedBytes
	stats.TotalDroppedBytes = counter.DroppedBytes
	stats.TotalAcceptedPackets = counter.AcceptedPackets
	stats.TotalDroppedPackets = counter.DroppedPackets

	now := time.Now()
	if !p.lastCheckTime.IsZero() {
		duration := now.Sub(p.lastCheckTime).Seconds()
		if duration > 0 {
			bytesDiff := float64(stats.TotalAcceptedBytes - p.lastBytes)
			// avoid overflow
			if stats.TotalAcceptedBytes < p.lastBytes {
				bytesDiff = 0
			}

			instantRate := bytesDiff / duration
			stats.InstantRateBps = instantRate

			// EMA - Exponential Moving Average
			const alpha = 0.2
			if p.smoothRate == 0 {
				p.smoothRate = instantRate
			} else {
				p.smoothRate = (alpha * instantRate) + ((1 - alpha) * p.smoothRate)
			}
			stats.SmoothRateBps = p.smoothRate
		}
	}

	p.lastCheckTime = now
	p.lastBytes = stats.TotalAcceptedBytes

	return stats
}
