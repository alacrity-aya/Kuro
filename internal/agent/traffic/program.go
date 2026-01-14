package traffic

import (
	"fmt"
	"math"
	"time"

	"github.com/alacrity-aya/Kuro/internal/bpf"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

type BpfProgram struct {
	podName     string
	ifaceIndex  uint32
	ifaceName   string
	currentSpec Spec

	objs        *bpf.TcObjects
	ingressLink link.Link
	egressLink  link.Link
	loaded      bool

	lastCheckTime time.Time

	// Ingress History
	lastIngressBytes  uint64
	smoothIngressRate float64

	// Egress History
	lastEgressBytes  uint64
	smoothEgressRate float64
}

// apply initialize or update traffic rules
func (p *BpfProgram) apply(sp Spec) error {
	p.ifaceIndex = uint32(sp.IfaceIndex)
	p.podName = sp.PodName
	p.currentSpec = sp

	if linkObj, err := netlink.LinkByIndex(sp.IfaceIndex); err == nil {
		p.ifaceName = linkObj.Attrs().Name
		p.currentSpec.IfaceName = p.ifaceName
	} else {
		p.ifaceName = fmt.Sprintf("ifindex-%d", sp.IfaceIndex)
	}

	if !p.loaded {
		p.objs = &bpf.TcObjects{}
		// TODO: what is this? Programs: ebpf.ProgramOptions{LogSizeStart: 2097152}?
		opts := &ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{LogSizeStart: 2097152},
		}
		if err := bpf.LoadTcObjects(p.objs, opts); err != nil {
			return fmt.Errorf("failed to load ebpf objects: %w", err)
		}
		p.loaded = true
	}

	trafficRule := bpf.TcTrafficRule{
		RateBytes:  sp.RateLimit.RateBytes,
		BurstBytes: sp.RateLimit.BurstBytes,
	}
	if err := p.objs.TrafficRuleMap.Put(p.ifaceIndex, trafficRule); err != nil {
		return fmt.Errorf("update traffic map: %w", err)
	}

	lossThreshold := uint32(0)
	if sp.Netem.LossPercent > 0 {
		lossThreshold = uint32((sp.Netem.LossPercent / 100.0) * math.MaxUint32)
	}
	netemRule := bpf.TcNetemRule{
		DelayMs:       uint64(sp.Netem.LatencyMs),
		JitterMs:      uint64(sp.Netem.JitterMs),
		LossThreshold: lossThreshold,
	}
	if err := p.objs.NetemRuleMap.Put(p.ifaceIndex, netemRule); err != nil {
		return fmt.Errorf("update netem map: %w", err)
	}

	bucketState := bpf.TcBucketState{
		Tokens: sp.RateLimit.BurstBytes,
		LastNs: uint64(time.Now().UnixNano()),
	}

	// initialize bpf map
	p.objs.BucketStateMap.Update(p.ifaceIndex, bucketState, ebpf.UpdateNoExist)
	p.objs.FlowCounterMap.Update(p.ifaceIndex, []bpf.TcFlowCounter{}, ebpf.UpdateNoExist)

	if err := p.ensureFQ(); err != nil {
		return fmt.Errorf("ensure fq: %w", err)
	}

	if p.ingressLink == nil {
		l, err := link.AttachTCX(link.TCXOptions{
			Program:   p.objs.Ingress,
			Interface: int(p.ifaceIndex),
			Attach:    ebpf.AttachTCXIngress,
		})
		if err != nil {
			return fmt.Errorf("attach ingress: %w", err)
		}
		p.ingressLink = l
	}

	if p.egressLink == nil {
		l, err := link.AttachTCX(link.TCXOptions{
			Program:   p.objs.Egress,
			Interface: int(p.ifaceIndex),
			Attach:    ebpf.AttachTCXEgress,
		})
		if err != nil {
			return fmt.Errorf("attach egress: %w", err)
		}
		p.egressLink = l
	}

	return nil
}

// ensureFQ: we use fq to analog delay effect
func (p *BpfProgram) ensureFQ() error {
	linkObj, err := netlink.LinkByIndex(int(p.ifaceIndex))
	if err != nil {
		return err
	}
	qdiscs, err := netlink.QdiscList(linkObj)
	if err != nil {
		return err
	}
	for _, q := range qdiscs {
		if q.Attrs().Parent == netlink.HANDLE_ROOT && q.Type() == "fq" {
			return nil
		}
	}
	fq := netlink.NewFq(netlink.QdiscAttrs{
		LinkIndex: linkObj.Attrs().Index,
		Parent:    netlink.HANDLE_ROOT,
		Handle:    netlink.MakeHandle(1, 0),
	})
	return netlink.QdiscAdd(fq)
}

func (p *BpfProgram) cleanUp() error {
	if !p.loaded {
		return nil
	}

	if p.ingressLink != nil {
		p.ingressLink.Close()
	}
	if p.egressLink != nil {
		p.egressLink.Close()
	}
	if p.objs != nil {
		p.objs.Close()
	}
	p.removeFQ()
	p.loaded = false
	return nil
}

func (p *BpfProgram) removeFQ() error {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: int(p.ifaceIndex),
			Parent:    netlink.HANDLE_ROOT,
		},
		QdiscType: "fq",
	}
	return netlink.QdiscDel(qdisc)
}

func (p *BpfProgram) getStats() TrafficStats {
	stats := TrafficStats{
		PodName:     p.podName,
		IfaceName:   p.ifaceName,
		CurrentSpec: &p.currentSpec,
	}

	if !p.loaded || p.objs == nil {
		return stats
	}

	var counters []bpf.TcFlowCounter
	if err := p.objs.FlowCounterMap.Lookup(p.ifaceIndex, &counters); err == nil {
		for _, c := range counters {
			// Ingress
			stats.Ingress.TotalBytes += c.RxBytes
			stats.Ingress.TotalPackets += c.RxPackets
			stats.Ingress.DroppedBytes += c.RxDroppedBytes
			stats.Ingress.DroppedPackets += c.RxDroppedPackets

			// Egress
			stats.Egress.TotalBytes += c.TxBytes
			stats.Egress.TotalPackets += c.TxPackets
			stats.Egress.DroppedBytes += c.TxDroppedBytes
			stats.Egress.DroppedPackets += c.TxDroppedPackets
		}
	}

	now := time.Now()
	if !p.lastCheckTime.IsZero() {
		duration := now.Sub(p.lastCheckTime).Seconds()
		if duration > 0 {
			stats.Ingress.InstantRateBps, stats.Ingress.SmoothRateBps = calculateRate(
				stats.Ingress.TotalBytes, p.lastIngressBytes, p.smoothIngressRate, duration,
			)
			stats.Egress.InstantRateBps, stats.Egress.SmoothRateBps = calculateRate(
				stats.Egress.TotalBytes, p.lastEgressBytes, p.smoothEgressRate, duration,
			)
		}
	}

	p.lastCheckTime = now
	p.lastIngressBytes = stats.Ingress.TotalBytes
	p.smoothIngressRate = stats.Ingress.SmoothRateBps
	p.lastEgressBytes = stats.Egress.TotalBytes
	p.smoothEgressRate = stats.Egress.SmoothRateBps

	return stats
}

func calculateRate(current, last uint64, smoothRate, duration float64) (float64, float64) {
	bytesDiff := float64(0)
	if current >= last {
		bytesDiff = float64(current - last)
	}

	instant := bytesDiff / duration

	// EMA alpha = 0.2
	const alpha = 0.2
	newSmooth := instant
	if smoothRate != 0 {
		newSmooth = (alpha * instant) + ((1 - alpha) * smoothRate)
	}

	return instant, newSmooth
}
