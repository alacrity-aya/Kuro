package traffic

import (
	"fmt"
	"log/slog"
	"math"
	"runtime"
	"time"

	"github.com/alacrity-aya/Kuro/internal/bpf"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

type flowHistory struct {
	lastIngressBytes  uint64
	smoothIngressRate float64
	lastEgressBytes   uint64
	smoothEgressRate  float64
}

// TODO: maybe need a NewBpfProgram function here
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

	history map[uint32]*flowHistory
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
		p.history = make(map[uint32]*flowHistory)
		p.loaded = true
	}
	if err := p.updateRule(uint32(sp.IfaceIndex), 0, sp.DefaultRule); err != nil {
		return err
	}

	for _, rule := range sp.Rules {
		ipInt, err := IPToUint32(rule.TargetIP)
		if err != nil {
			slog.Warn("Invalid target IP in rule", "ip", rule.TargetIP)
			continue
		}
		if err := p.updateRule(uint32(sp.IfaceIndex), ipInt, rule); err != nil {
			return err
		}
	}

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

func (p *BpfProgram) updateRule(ifindex uint32, ip uint32, rule Rule) error {
	// TODO: don't init bpf map in this function
	key := bpf.TcRuleKey{
		Ifindex: ifindex,
		Ipv4:    ip,
	}

	// Traffic Rule
	tr := bpf.TcTrafficRule{
		RateBytes:  rule.Rate.RateBytes,
		BurstBytes: rule.Rate.BurstBytes,
	}
	if err := p.objs.TrafficRuleMap.Put(key, tr); err != nil {
		return err
	}

	// Netem Rule
	nr := bpf.TcNetemRule{
		DelayMs:       uint64(rule.Netem.LatencyMs),
		JitterMs:      uint64(rule.Netem.JitterMs),
		LossThreshold: uint32((rule.Netem.LossPercent / 100.0) * math.MaxUint32),
	}
	if err := p.objs.NetemRuleMap.Put(key, nr); err != nil {
		return err
	}

	// init bucket state
	if rule.Rate.RateBytes > 0 {
		bs := bpf.TcBucketState{
			Tokens: rule.Rate.BurstBytes,
			LastNs: uint64(time.Now().UnixNano()),
		}
		if err := p.objs.BucketStateMap.Update(key, bs, ebpf.UpdateNoExist); err != nil {
			// TODO: handler err here
			slog.Warn("init bucket state", "error", err)
		}
	}

	// init flow counter
	emptyCounters := make([]bpf.TcFlowCounter, runtime.NumCPU())
	if err := p.objs.FlowCounterMap.Update(key, emptyCounters, ebpf.UpdateNoExist); err != nil {
		// TODO: handler err here
		slog.Warn("init flow counter", "error", err)
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
	// TODO: log should be removed
	statsMap := make(map[string]*LinkStats, len(p.history))
	result := TrafficStats{
		PodName:     p.podName,
		IfaceName:   p.ifaceName,
		CurrentSpec: &p.currentSpec,
		Stats:       statsMap,
	}

	if !p.loaded || p.objs == nil {
		return result
	}

	now := time.Now()
	var duration float64
	calculateRateFlag := false

	if !p.lastCheckTime.IsZero() {
		duration = now.Sub(p.lastCheckTime).Seconds()
		if duration > 0.001 {
			calculateRateFlag = true
		}
	}

	slog.Info("Starting CollectStats", "pod", p.podName, "expect_ifindex", p.ifaceIndex)
	iter := p.objs.FlowCounterMap.Iterate()
	var key bpf.TcRuleKey
	var counters []bpf.TcFlowCounter

	currentActiveIPs := make(map[uint32]struct{}, len(p.history))

	countItems := 0
	for iter.Next(&key, &counters) {

		countItems++
		slog.Debug("Map Item Found",
			"key_ifindex", key.Ifindex,
			"key_ip_hex", fmt.Sprintf("%x", key.Ipv4),
			"target_ifindex", p.ifaceIndex,
			"matched", key.Ifindex == p.ifaceIndex,
		)

		if key.Ifindex != p.ifaceIndex {
			continue
		}

		currentActiveIPs[key.Ipv4] = struct{}{}

		var rxBytes, rxPkts, rxDropBytes, rxDropPkts uint64
		var txBytes, txPkts, txDropBytes, txDropPkts uint64

		for _, c := range counters {
			rxBytes += c.RxBytes
			rxPkts += c.RxPackets
			rxDropBytes += c.RxDroppedBytes
			rxDropPkts += c.RxDroppedPackets

			txBytes += c.TxBytes
			txPkts += c.TxPackets
			txDropBytes += c.TxDroppedBytes
			txDropPkts += c.TxDroppedPackets
		}

		ipStr := Uint32ToIP(key.Ipv4)

		linkStat := &LinkStats{
			RemoteIP: ipStr,
			Ingress: DirectionStats{
				TotalBytes:     rxBytes,
				TotalPackets:   rxPkts,
				DroppedBytes:   rxDropBytes,
				DroppedPackets: rxDropPkts,
			},
			Egress: DirectionStats{
				TotalBytes:     txBytes,
				TotalPackets:   txPkts,
				DroppedBytes:   txDropBytes,
				DroppedPackets: txDropPkts,
			},
		}

		if calculateRateFlag {
			hist, exists := p.history[key.Ipv4]
			if !exists {
				hist = &flowHistory{}
				p.history[key.Ipv4] = hist
			}

			linkStat.Ingress.InstantRateBps, linkStat.Ingress.SmoothRateBps = calculateRate(
				rxBytes, hist.lastIngressBytes, hist.smoothIngressRate, duration,
			)
			linkStat.Egress.InstantRateBps, linkStat.Egress.SmoothRateBps = calculateRate(
				txBytes, hist.lastEgressBytes, hist.smoothEgressRate, duration,
			)

			hist.lastIngressBytes = rxBytes
			hist.smoothIngressRate = linkStat.Ingress.SmoothRateBps
			hist.lastEgressBytes = txBytes
			hist.smoothEgressRate = linkStat.Egress.SmoothRateBps
		} else {
			if _, exists := p.history[key.Ipv4]; !exists {
				p.history[key.Ipv4] = &flowHistory{
					lastIngressBytes: rxBytes,
					lastEgressBytes:  txBytes,
				}
			}
		}
		slog.Debug("Stats Raw Data",
			"ip", ipStr,
			"rx_bytes", rxBytes,
			"tx_bytes", txBytes,
		)

		statsMap[ipStr] = linkStat
	}

	if countItems == 0 {
		slog.Debug("Map is empty! No items found during iteration.")
	}

	if err := iter.Err(); err != nil {
		slog.Error("map iteration failed", "err", err)
	}

	if len(p.history) > len(currentActiveIPs) {
		for ipInt := range p.history {
			if _, ok := currentActiveIPs[ipInt]; !ok {
				delete(p.history, ipInt)
			}
		}
	}

	p.lastCheckTime = now
	return result
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
