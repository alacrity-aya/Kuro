// Package loader is used to load ebpf program
package loader

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"kuro/gen"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
)

func init() {
	if err := rlimit.RemoveMemlock(); err != nil {
		slog.Error("Failed to remove memlock", "error", err)
	}
}

type IfaceStats struct {
	IfaceName string
	Stat      TrafficStats
}

type TrafficStats struct {
	TotalAcceptedBytes   uint64
	TotalDroppedBytes    uint64
	TotalAcceptedPackets uint64
	TotalDroppedPackets  uint64

	// Calculated rates (based on AcceptedBytes)
	InstantRateBps float64 // Bytes per second (Instantaneous)
	SmoothRateBps  float64 // Bytes per second (Smoothed/EMA)

	TimeStamp time.Time
}

type EbpfProgram struct {
	links []link.Link
	objs  *gen.TcObjects

	loaded bool

	ifaceIndex uint32

	// Field for rate cauculation
	lastCheck   time.Time
	lastBytes   uint64
	smoothRate  float64
	firstSample bool
	statsMu     sync.Mutex
}

func NewEbpfProgram(objs *gen.TcObjects) *EbpfProgram {
	loaded := objs != nil && objs.Gress != nil

	return &EbpfProgram{
		objs:        objs,
		links:       make([]link.Link, 0),
		firstSample: true,
		loaded:      loaded,
	}
}

func (p *EbpfProgram) Detach() error {
	var errs []error
	for _, l := range p.links {
		if l != nil {
			if err := l.Close(); err != nil {
				errs = append(errs, err)
				slog.Error("Failed to close link", "error", err)
			}
		}
	}
	p.links = nil
	if len(errs) > 0 {
		return fmt.Errorf("errors occurred during detach: %v", errs)
	}
	return nil
}

func (p *EbpfProgram) ensureFQ(ifaceName string) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return err
	}

	qdisc, err := netlink.QdiscList(link)
	if err != nil {
		return err
	}

	for _, q := range qdisc {
		if q.Type() == "fq" {
			slog.Warn("qdisc 'fq' has existed", "ifaceName", ifaceName)
			return nil
		}
	}

	fq := netlink.NewFq(netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(1, 0),
		Parent:    netlink.HANDLE_ROOT,
	})

	return netlink.QdiscAdd(fq)
}

// Attach I think attaching ingress only is enough
func (p *EbpfProgram) Attach(ifaceName string) error {
	if p.objs == nil || p.objs.Gress == nil {
		return fmt.Errorf("ebpf objects or program not loaded")
	}
	if !p.loaded {
		return fmt.Errorf("program not loaded, call Load() first")
	}

	if err := p.ensureFQ(ifaceName); err != nil {
		slog.Error("Failed to setup FQ qdisc, netem rule will fail", "iface", ifaceName, "error", err)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", ifaceName, err)
	}

	p.ifaceIndex = uint32(iface.Index)

	// Detach existing links
	_ = p.Detach()

	var newLinks []link.Link

	// TODO: remove this in future
	attachDir := func(attachType ebpf.AttachType) error {
		l, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   p.objs.Gress,
			Attach:    attachType,
		})
		if err != nil {
			return err
		}
		newLinks = append(newLinks, l)
		return nil
	}

	if err := attachDir(ebpf.AttachTCXIngress); err != nil {
		return err
	}

	p.links = newLinks
	p.firstSample = true
	p.lastCheck = time.Now()

	slog.Info("Attached eBPF program", "iface", ifaceName, "index", p.ifaceIndex, "gress", "ingress")
	return nil
}

func (p *EbpfProgram) UpdateNetem(delayMs, jitterMs, loss float64) error {
	if !p.loaded {
		return fmt.Errorf("program not loaded")
	}
	// 4294967295 = 0xFFFFFFFF(max value of uint32)
	lossThreshold := uint64((loss / 100.0) * 4294967295)

	rule := gen.TcNetemRule{
		LossThreshold: lossThreshold,
		JitterMs:      uint64(jitterMs),
		DelayMs:       uint64(delayMs),
	}

	slog.Debug("Updating NetemRuleMap",
		"ifaceIdx", p.ifaceIndex,
		"delay", rule.DelayMs,
		"jitter", rule.JitterMs,
		"loss", loss,
		"lossThreshold", rule.LossThreshold)

	if err := p.objs.NetemRuleMap.Update(p.ifaceIndex, rule, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update netem map: %w", err)
	}

	return nil
}

func (p *EbpfProgram) UpdateRateLimit(rate, burst uint64) error {
	if !p.loaded {
		return fmt.Errorf("program not loaded")
	}

	// Ensure State Map entry exists (needed for HASH maps with spinlocks)
	// We must initialize the bucket state if it doesn't exist
	newState := gen.TcBucketState{
		Tokens: burst, // Give full burst initially
		LastNs: uint64(time.Now().UnixNano()),
	}
	if err := p.objs.BucketStateMap.Update(p.ifaceIndex, newState, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to init bucket state: %w", err)
	}
	slog.Debug("Initialized bucket state", "state", newState)

	rule := gen.TcTrafficRule{
		RateBytes:  rate,
		BurstBytes: burst,
	}

	slog.Debug("Updating BucketRuleMap", "ifaceIdx", p.ifaceIndex, "rate", rate, "burst", burst)

	if err := p.objs.TrafficRuleMap.Update(p.ifaceIndex, rule, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update rate limit map: %w", err)
	}

	return nil
}

func (p *EbpfProgram) GetStats() (TrafficStats, error) {
	p.statsMu.Lock()
	defer p.statsMu.Unlock()

	var stats TrafficStats
	if !p.loaded {
		return stats, fmt.Errorf("program not loaded")
	}

	// initialize flow counter map
	if p.firstSample {
		if err := initFlowCounterMap(p); err != nil {
			return TrafficStats{}, err
		}
	}

	var values []gen.TcFlowCounter

	if err := p.objs.FlowCounterMap.Lookup(p.ifaceIndex, &values); err != nil {
		return stats, nil
	}

	for _, v := range values {
		stats.TotalAcceptedBytes += v.AcceptedBytes
		stats.TotalDroppedBytes += v.DroppedBytes
		stats.TotalAcceptedPackets += v.AcceptedPackets
		stats.TotalDroppedPackets += v.DroppedPackets
	}

	now := time.Now()
	stats.TimeStamp = now

	if p.firstSample {
		p.lastBytes = stats.TotalAcceptedBytes
		p.lastCheck = now
		p.smoothRate = 0
		p.firstSample = false
		return stats, nil
	}

	duration := now.Sub(p.lastCheck).Seconds()

	if duration > 0 {
		deltaBytes := float64(stats.TotalAcceptedBytes - p.lastBytes)
		stats.InstantRateBps = deltaBytes / duration

		alpha := 0.2
		if p.smoothRate == 0 {
			p.smoothRate = stats.InstantRateBps
		} else {
			p.smoothRate = (alpha * stats.InstantRateBps) + ((1 - alpha) * p.smoothRate)
		}
		stats.SmoothRateBps = p.smoothRate
	}

	p.lastBytes = stats.TotalAcceptedBytes
	p.lastCheck = now

	return stats, nil
}

func initFlowCounterMap(prog *EbpfProgram) error {
	var counterVals []gen.TcFlowCounter
	key := prog.ifaceIndex
	if err := prog.objs.FlowCounterMap.Update(key, counterVals, ebpf.UpdateNoExist); err != nil {
		return fmt.Errorf("init flow counter failed: %w", err)
	}
	slog.Debug("Initialized flow counter entry", "ifaceIdx", key)

	return nil
}
