package loader

import (
	"encoding/binary"
	"fmt"
	"net"

	"kuro/gen"
)

type EbpfMetadata struct {
	Programs []ProgramMetadata
	Routes   []RouteMetadata
}

type ProgramMetadata struct {
	IfaceName  string
	IfaceIndex uint32
	IsLoaded   bool
	RateLimit  *RateLimitMetadata
}

type RateLimitMetadata struct {
	RateBytes  uint64
	BurstBytes uint64
}

type RouteMetadata struct {
	DestIP      string
	TargetIndex uint32
}

func (m *EbpfManager) GetMetadata() EbpfMetadata {
	m.mu.RLock()
	defer m.mu.RUnlock()

	metadata := EbpfMetadata{
		Programs: make([]ProgramMetadata, 0),
		Routes:   make([]RouteMetadata, 0),
	}

	for name, prog := range m.programs {
		pMeta := ProgramMetadata{
			IfaceName:  name,
			IfaceIndex: prog.ifaceIndex,
			IsLoaded:   prog.loaded,
		}

		var rule gen.TcTrafficRule
		if m.objs != nil && m.objs.TrafficRuleMap.Lookup(prog.ifaceIndex, &rule) == nil {
			pMeta.RateLimit = &RateLimitMetadata{
				RateBytes:  rule.RateBytes,
				BurstBytes: rule.BurstBytes,
			}
		}
		metadata.Programs = append(metadata.Programs, pMeta)
	}

	if m.objs != nil && m.objs.RedirectMap != nil {
		var (
			key    uint32
			val    uint32
			cursor = m.objs.RedirectMap.Iterate()
		)
		for cursor.Next(&key, &val) {
			// be32 -> ip string
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, key)

			metadata.Routes = append(metadata.Routes, RouteMetadata{
				DestIP:      ip.String(),
				TargetIndex: val,
			})
		}
	}

	return metadata
}

func (m *EbpfManager) InspectMetadata() {
	meta := m.GetMetadata()
	fmt.Println("--- eBPF Runtime Metadata Inspection ---")

	fmt.Println("Attached Programs:")
	for _, p := range meta.Programs {
		status := "LOADED"
		if !p.IsLoaded {
			status = "NOT_LOADED"
		}

		limitStr := "None"
		if p.RateLimit != nil {
			limitStr = fmt.Sprintf("Rate:%d, Burst:%d", p.RateLimit.RateBytes, p.RateLimit.BurstBytes)
		}

		fmt.Printf("  [Iface: %-10s | Index: %-3d] Status: %-10s | TC-Limit: %s\n",
			p.IfaceName, p.IfaceIndex, status, limitStr)
	}

	fmt.Println("Redirect Routes (L3):")
	if len(meta.Routes) == 0 {
		fmt.Println("  No redirect routes found in Map.")
	}
	for _, r := range meta.Routes {
		fmt.Printf("  Destination: %-15s => Target Iface Index: %d\n", r.DestIP, r.TargetIndex)
	}
}
