package loader

import (
	"log"
	"log/slog"
	"net"

	"kuro/config"
	"kuro/gen"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type EbpfResource struct {
	links []link.Link
	objs  gen.TcObjects
}

func (r *EbpfResource) Close() {
	slog.Info("Starting eBPF resource cleanup...")

	// close links
	closeLinks(r.links...)

	r.links = nil

	// close objs
	if err := r.objs.Close(); err != nil {
		slog.Error("Failed to close eBPF objects", "error", err)
	}

	slog.Info("eBPF resource cleanup finished.")
}

func closeLinks(links ...link.Link) {
	for _, l := range links {
		if l != nil {
			if err := l.Close(); err != nil {
				slog.Error("Failed to close eBPF link", "error", err)
			}
		}
	}
}

func LoadEbpf(cfg *config.Config) *EbpfResource {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	var resource EbpfResource

	objs := gen.TcObjects{}

	resource.objs = objs

	if err := gen.LoadTcObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}

	count := 0

	for _, rule := range cfg.Rules {
		iface, err := net.InterfaceByName(rule.Ifacename)
		if err != nil {
			slog.Error("find interface by name failed", "Ifacename", rule.Ifacename)
			continue
		}

		links, err := attachTCX(rule.Gress, iface.Index, objs)
		if err != nil {
			slog.Error("Count not attach TCx program", "ifaceIndex", iface.Index, "gress", rule.Gress)
			continue
		} else {
			slog.Debug("attach TCx program", "ifaceName", rule.Ifacename, "gress", rule.Gress)
		}

		err = updateRule(rule.RateLimit.Rate, rule.RateLimit.Burst, objs)
		if err != nil {
			slog.Error("failed to update map, start to cleanup links", "rate", rule.RateLimit.Rate, "burst", rule.RateLimit.Burst)
			closeLinks(links...)
			continue
		}

		resource.links = append(resource.links, links...)

		count++

	}

	slog.Debug("after attaching", "count", count)
	return &resource
}

func updateRule(rate, burst uint64, objs gen.TcObjects) error {
	rule := gen.TcBucketRule{
		RateBytes:  rate,
		BurstBytes: burst,
	}

	var key uint32 = 0

	slog.Debug("update BucketRuleMap", "key", key, "rule", rule)
	err := objs.BucketRuleMap.Update(key, rule, ebpf.UpdateAny)
	if err != nil {
		return err
	}

	return nil
}

func attachTCX(gress string, ifaceIndex int, objs gen.TcObjects) ([]link.Link, error) {
	var links []link.Link

	if gress != "both" {

		gressType := ebpf.AttachTCXEgress
		if gress == "ingress" {
			gressType = ebpf.AttachTCXIngress
		}

		l, err := link.AttachTCX(link.TCXOptions{Interface: ifaceIndex, Program: objs.Gress, Attach: gressType})
		if err != nil {
			return nil, err
		}
		links = append(links, l)
		return links, nil
	}

	l1, err := link.AttachTCX(link.TCXOptions{Interface: ifaceIndex, Program: objs.Gress, Attach: ebpf.AttachTCXEgress})
	if err != nil {
		return nil, err
	}

	l2, err := link.AttachTCX(link.TCXOptions{Interface: ifaceIndex, Program: objs.Gress, Attach: ebpf.AttachTCXIngress})
	if err != nil {
		l1.Close()
		return nil, err
	}

	links = append(links, l1, l2)
	return links, nil
}
