// Package bpf
package bpf

import (
	"fmt"
	"log"
	"runtime"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// NOTE: these constants must be consistent with ebpf defines
const (
	NsecPerSec    = 1000000000
	ScaleFactor   = 65536
	MaxIfIndexCap = 4096
)

// BpfManager manages eBPF programs and maps for traffic control.
type BpfManager struct {
	mu      sync.RWMutex
	objects *TcObjects
	// programs map key is HostIfIndex.
	programs map[int]*BpfProgram

	eth0EgressLink  link.Link
	eth0IngressLink link.Link
}

type BpfProgram struct {
	// Links
	hostEgressLink link.Link
	podEgressLink  link.Link

	// Metadata
	podName     string
	hostIfIndex int
	podIfIndex  int // The interface index inside the container
	netnsHandle netns.NsHandle
	// TODO: store rate limiation here
}

// NewBpfManager loads the BPF programs and initializes global configurations.
func NewBpfManager() (*BpfManager, error) {
	objs := &TcObjects{}
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSizeStart: 64 * 1024 * 1024,
		},
	}

	if err := LoadTcObjects(objs, opts); err != nil {
		return nil, fmt.Errorf("loading tc objects: %w", err)
	}

	key := uint32(0)
	config := TcGlobalConfig{
		EdtHorizonNs: 5 * 100 * 1000 * 1000, // 500 ms
	}
	if err := objs.ConfigMap.Put(&key, &config); err != nil {
		objs.Close()
		return nil, fmt.Errorf("initializing config map: %w", err)
	}

	mgr := &BpfManager{
		objects:  objs,
		programs: make(map[int]*BpfProgram),
	}

	return mgr, nil
}

func (m *BpfManager) AttachNICEgress(hostInterface string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	hostLink, err := netlink.LinkByName(hostInterface)
	if err != nil {
		return fmt.Errorf("failed to find host iface %s: %w", hostInterface, err)
	}
	hostIfIndex := hostLink.Attrs().Index

	if err = m.ensureFQ(hostIfIndex, 0); err != nil {
		return fmt.Errorf("failed to ensure fq on %s: %w", hostInterface, err)
	}

	m.eth0EgressLink, err = link.AttachTCX(link.TCXOptions{
		Program:   m.objects.HandleEth0Egress,
		Interface: hostIfIndex,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return fmt.Errorf("attach host egress: %w", err)
	}
	return nil
}

func (m *BpfManager) AttachIngressProtection(hostInterface string, limitBps uint64, burstBytes uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if limitBps == 0 {
		speedMbps, err := getInterfaceSpeed(hostInterface)
		if err != nil || speedMbps == 0 {
			speedMbps = 1000
		}
		limitBps = (speedMbps * 1000 * 1000) * 90 / 100
	}

	hostLink, err := netlink.LinkByName(hostInterface)
	if err != nil {
		return fmt.Errorf("failed to find host iface %s: %w", hostInterface, err)
	}
	hostIfIndex := hostLink.Attrs().Index

	const (
		NsecPerSec  = 1000000000
		ScaleFactor = 65536 // 2^16
	)

	costPerByteScaled := uint64((float64(8*NsecPerSec) * float64(ScaleFactor)) / float64(limitBps))
	burstNs := (burstBytes * 8 * NsecPerSec) / limitBps

	ingressCfg := TcIngressConfig{
		CostPerByteNsScaled: costPerByteScaled,
		BurstNs:             burstNs,
	}

	key0 := uint32(0)
	if err = m.objects.IngressConfigMap.Put(&key0, &ingressCfg); err != nil {
		return fmt.Errorf("update ingress config: %w", err)
	}

	ingressState := TcIngressState{
		LastUpdated: 0,
		TokensNs:    burstNs,
	}
	if err = m.objects.IngressStateMap.Put(&key0, &ingressState); err != nil {
		return fmt.Errorf("init ingress state: %w", err)
	}

	if m.eth0IngressLink != nil {
		m.eth0IngressLink.Close()
	}

	m.eth0IngressLink, err = link.AttachXDP(link.XDPOptions{
		Program:   m.objects.HandleXdpIngress,
		Interface: hostIfIndex,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		m.eth0IngressLink, err = link.AttachXDP(link.XDPOptions{
			Program:   m.objects.HandleXdpIngress,
			Interface: hostIfIndex,
			Flags:     link.XDPGenericMode,
		})
	}

	if err != nil {
		return fmt.Errorf("attach xdp: %w", err)
	}

	return nil
}

func (m *BpfManager) AddPod(podName string, hostIfIndex int, nsHandle netns.NsHandle) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if hostIfIndex >= MaxIfIndexCap {
		return fmt.Errorf("ifindex too large")
	}

	if _, ok := m.programs[hostIfIndex]; ok {
		return nil
	}

	log.Printf("[BPF] Setting up Pod %s (HostIfIndex: %d)", podName, hostIfIndex)

	prog := &BpfProgram{
		podName:     podName,
		hostIfIndex: hostIfIndex,
		netnsHandle: nsHandle,
	}

	// 1. Ensure FQ and Attach Download Prog
	if err := m.ensureFQ(hostIfIndex, 0); err != nil {
		return fmt.Errorf("host fq: %w", err)
	}

	hostLink, err := link.AttachTCX(link.TCXOptions{
		Program:   m.objects.HandleEdtDownload,
		Interface: hostIfIndex,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return fmt.Errorf("attach host egress: %w", err)
	}
	prog.hostEgressLink = hostLink

	// Init State Maps
	initEdtState := TcEdtState{}
	keyHostSys := uint32(hostIfIndex * 2)
	keyHostSim := uint32(hostIfIndex*2 + 1)

	if err = m.objects.EdtDownloadStateMap.Update(&keyHostSys, &initEdtState, ebpf.UpdateAny); err != nil {
		hostLink.Close()
		return fmt.Errorf("init download sys state: %w", err)
	}
	if err = m.objects.EdtDownloadStateMap.Update(&keyHostSim, &initEdtState, ebpf.UpdateAny); err != nil {
		hostLink.Close()
		return fmt.Errorf("init download sim state: %w", err)
	}

	// 2. Setup Pod Egress
	podIfIndex, podLink, err := m.setupPodEgress(nsHandle)
	if err != nil {
		hostLink.Close()
		return fmt.Errorf("pod side setup failed: %w", err)
	}

	prog.podIfIndex = podIfIndex
	prog.podEgressLink = podLink

	// Init Upload State Maps
	keyPodSys := uint32(prog.podIfIndex * 2)
	keyPodSim := uint32(prog.podIfIndex*2 + 1)

	if err := m.objects.EdtUploadStateMap.Update(&keyPodSys, &initEdtState, ebpf.UpdateAny); err != nil {
		hostLink.Close()
		prog.podEgressLink.Close()
		return fmt.Errorf("init upload sys state: %w", err)
	}
	if err := m.objects.EdtUploadStateMap.Update(&keyPodSim, &initEdtState, ebpf.UpdateAny); err != nil {
		hostLink.Close()
		prog.podEgressLink.Close()
		return fmt.Errorf("init upload sim state: %w", err)
	}

	// 3. Initialize Metrics Map (PerCPU)
	zeroStats := make([]TcPodStats, runtime.NumCPU())
	key := uint32(hostIfIndex)
	if err := m.objects.MetricsMap.Put(&key, zeroStats); err != nil {
		log.Printf("[BPF] Warning: Failed to init metrics map for %s: %v", podName, err)
	}

	// 4. Initialize Latency Histogram Map (PerCPU)
	zeroHist := make([]TcLatencyHist, runtime.NumCPU())
	if err := m.objects.LatencyMap.Put(&key, zeroHist); err != nil {
		log.Printf("[BPF] Warning: Failed to init latency map for %s: %v", podName, err)
	}

	m.programs[hostIfIndex] = prog
	return nil
}

func (m *BpfManager) setupPodEgress(podNsHandle netns.NsHandle) (int, link.Link, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hostNs, err := netns.Get()
	if err != nil {
		return 0, nil, fmt.Errorf("failed to get current netns: %w", err)
	}
	defer hostNs.Close()

	if err = netns.Set(podNsHandle); err != nil {
		return 0, nil, fmt.Errorf("failed to enter pod netns: %w", err)
	}

	defer func() {
		if err = netns.Set(hostNs); err != nil {
			log.Printf("[CRITICAL] Failed to restore host netns: %v", err)
		}
	}()

	links, err := netlink.LinkList()
	if err != nil {
		return 0, nil, fmt.Errorf("list links in pod: %w", err)
	}

	var targetLink netlink.Link
	for _, l := range links {
		if l.Attrs().Name != "lo" {
			targetLink = l
			break
		}
	}
	if targetLink == nil {
		return 0, nil, fmt.Errorf("no suitable interface (eth0) found in pod")
	}

	podIfIndex := targetLink.Attrs().Index

	if err = m.ensureFQ(podIfIndex, 0); err != nil {
		return 0, nil, fmt.Errorf("pod fq: %w", err)
	}

	ulLink, err := link.AttachTCX(link.TCXOptions{
		Program:   m.objects.HandleEdtUpload,
		Interface: podIfIndex,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return 0, nil, fmt.Errorf("attach pod egress: %w", err)
	}

	return podIfIndex, ulLink, nil
}

func (m *BpfManager) UpdateRule(hostIfIndex int, upSim, downSim, upSys, downSys uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	prog, ok := m.programs[hostIfIndex]
	if !ok {
		return fmt.Errorf("pod not found")
	}

	if hostIfIndex >= MaxIfIndexCap {
		return fmt.Errorf("ifindex %d exceeds max capacity %d", hostIfIndex, MaxIfIndexCap)
	}

	keyHost := uint32(hostIfIndex)
	rateCfgDown := TcIoRate{
		CostPerByteSimDownload: bpsToScaledCost(downSim),
		CostPerByteSysDownload: bpsToScaledCost(downSys),
	}
	if err := m.objects.RateMap.Update(&keyHost, &rateCfgDown, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update download rate: %w", err)
	}

	keyPod := uint32(prog.podIfIndex)
	rateCfgUp := TcIoRate{
		CostPerByteSimUpload: bpsToScaledCost(upSim),
		CostPerByteSysUpload: bpsToScaledCost(upSys),
	}
	if err := m.objects.RateMap.Update(&keyPod, &rateCfgUp, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update upload rate: %w", err)
	}

	return nil
}

func (m *BpfManager) RemovePod(hostIfIndex int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	prog, ok := m.programs[hostIfIndex]
	if !ok {
		return nil
	}

	if prog.hostEgressLink != nil {
		prog.hostEgressLink.Close()
	}
	if prog.podEgressLink != nil {
		prog.podEgressLink.Close()
	}

	zeroRate := TcIoRate{}
	zeroState := TcEdtState{}

	// Rate Map Clean
	keyHost := uint32(hostIfIndex)
	keyPod := uint32(prog.podIfIndex)
	_ = m.objects.RateMap.Update(&keyHost, &zeroRate, ebpf.UpdateAny)
	_ = m.objects.RateMap.Update(&keyPod, &zeroRate, ebpf.UpdateAny)

	// State Map Clean
	keyHostSys := uint32(hostIfIndex * 2)
	keyHostSim := uint32(hostIfIndex*2 + 1)
	_ = m.objects.EdtDownloadStateMap.Update(&keyHostSys, &zeroState, ebpf.UpdateAny)
	_ = m.objects.EdtDownloadStateMap.Update(&keyHostSim, &zeroState, ebpf.UpdateAny)

	keyPodSys := uint32(prog.podIfIndex * 2)
	keyPodSim := uint32(prog.podIfIndex*2 + 1)
	_ = m.objects.EdtUploadStateMap.Update(&keyPodSys, &zeroState, ebpf.UpdateAny)
	_ = m.objects.EdtUploadStateMap.Update(&keyPodSim, &zeroState, ebpf.UpdateAny)

	_ = m.objects.MetricsMap.Delete(&keyHost)
	_ = m.objects.LatencyMap.Delete(&keyHost)

	delete(m.programs, hostIfIndex)
	return nil
}

func (m *BpfManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, program := range m.programs {
		if program.hostEgressLink != nil {
			program.hostEgressLink.Close()
		}
		if program.podEgressLink != nil {
			program.podEgressLink.Close()
		}
	}

	if m.eth0EgressLink != nil {
		m.eth0EgressLink.Close()
	}
	if m.eth0IngressLink != nil {
		m.eth0IngressLink.Close()
	}

	return m.objects.Close()
}

func (m *BpfManager) AddPeer(ipStr string) error {
	ipUint, err := ipToUint32(ipStr)
	if err != nil {
		return err
	}
	val := uint8(1)
	if err := m.objects.SimulationPeersMap.Put(ipUint, val); err != nil {
		return fmt.Errorf("failed to add peer ip %s: %w", ipStr, err)
	}
	return nil
}

func (m *BpfManager) RemovePeer(ipStr string) error {
	ipUint, err := ipToUint32(ipStr)
	if err != nil {
		return err
	}
	if err := m.objects.SimulationPeersMap.Delete(ipUint); err != nil {
		if err != ebpf.ErrKeyNotExist {
			return fmt.Errorf("failed to remove peer ip %s: %w", ipStr, err)
		}
	}
	return nil
}

func (m *BpfManager) GetPeers() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var key uint32
	var val uint8
	var ips []string
	iter := m.objects.SimulationPeersMap.Iterate()
	for iter.Next(&key, &val) {
		ip := uint32ToIP(key)
		ips = append(ips, ip.String())
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("map iteration: %w", err)
	}
	return ips, nil
}

// PodMetricsResult includes latency data now
type PodMetricsResult struct {
	PodName     string        `json:"pod_name"`
	HostIfIndex int           `json:"host_ifindex"`
	Timestamp   int64         `json:"timestamp"` // Unix Nano
	Stats       TcPodStats    `json:"stats"`
	Latency     TcLatencyHist `json:"latency"`
}

func (m *BpfManager) CollectAllMetrics() ([]PodMetricsResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var results []PodMetricsResult

	for ifIndex, prog := range m.programs {
		key := uint32(ifIndex)

		// 1. Collect Flow Stats
		var statsPerCPU []TcPodStats
		if err := m.objects.MetricsMap.Lookup(&key, &statsPerCPU); err != nil {
			log.Printf("Failed to lookup metrics for pod %s: %v", prog.podName, err)
			continue
		}

		var totalStats TcPodStats
		for _, cpuStat := range statsPerCPU {
			// Sim Download
			totalStats.SimDownload.Packets += cpuStat.SimDownload.Packets
			totalStats.SimDownload.Bytes += cpuStat.SimDownload.Bytes
			totalStats.SimDownload.DropPackets += cpuStat.SimDownload.DropPackets
			totalStats.SimDownload.DropBytes += cpuStat.SimDownload.DropBytes

			// Sim Upload
			totalStats.SimUpload.Packets += cpuStat.SimUpload.Packets
			totalStats.SimUpload.Bytes += cpuStat.SimUpload.Bytes
			totalStats.SimUpload.DropPackets += cpuStat.SimUpload.DropPackets
			totalStats.SimUpload.DropBytes += cpuStat.SimUpload.DropBytes

			// Sys Download
			totalStats.SysDownload.Packets += cpuStat.SysDownload.Packets
			totalStats.SysDownload.Bytes += cpuStat.SysDownload.Bytes
			totalStats.SysDownload.DropPackets += cpuStat.SysDownload.DropPackets
			totalStats.SysDownload.DropBytes += cpuStat.SysDownload.DropBytes

			// Sys Upload
			totalStats.SysUpload.Packets += cpuStat.SysUpload.Packets
			totalStats.SysUpload.Bytes += cpuStat.SysUpload.Bytes
			totalStats.SysUpload.DropPackets += cpuStat.SysUpload.DropPackets
			totalStats.SysUpload.DropBytes += cpuStat.SysUpload.DropBytes
		}

		// 2. Collect Latency Histogram
		var latHists []TcLatencyHist
		var totalLatency TcLatencyHist

		// Best effort lookup for latency map
		if err := m.objects.LatencyMap.Lookup(&key, &latHists); err == nil {
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

// SyncPeers performs a full synchronization of the global whitelist.
// It removes IPs that are no longer in the list and adds new ones.
func (m *BpfManager) SyncPeers(newPeerIPs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 1. Convert new IPs to a Set (uint32) for O(1) lookups
	// 'desired' holds all IPs that SHOULD be in the map.
	desired := make(map[uint32]bool)
	for _, ipStr := range newPeerIPs {
		ipUint, err := ipToUint32(ipStr)
		if err != nil {
			log.Printf("[BPF] Warning: Skipping invalid peer IP '%s': %v", ipStr, err)
			continue
		}
		desired[ipUint] = true
	}

	// 2. Identify stale peers to remove
	// We iterate the current BPF map. If a key is NOT in 'desired', it must be deleted.
	// If it IS in 'desired', we remove it from the 'desired' map to mark it as "already exists".
	var toDelete []uint32

	var key uint32
	var val uint8
	iter := m.objects.SimulationPeersMap.Iterate()

	for iter.Next(&key, &val) {
		if _, keep := desired[key]; keep {
			// Peer exists in both BPF Map and New List.
			// Remove from 'desired' so we don't try to add it again later.
			delete(desired, key)
		} else {
			// Peer is in BPF Map but NOT in New List -> Mark for deletion.
			toDelete = append(toDelete, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("map iteration failed: %w", err)
	}

	// 3. Perform Deletions
	for _, ip := range toDelete {
		if err := m.objects.SimulationPeersMap.Delete(ip); err != nil {
			log.Printf("[BPF] Failed to delete stale peer IP: %v", err)
		} else {
			log.Printf("[BPF] Sync: Removed stale peer")
		}
	}

	// 4. Perform Additions
	// Any keys remaining in 'desired' are new peers that weren't in the map.
	addedCount := 0
	val = 1 // Whitelist flag
	for ip := range desired {
		if err := m.objects.SimulationPeersMap.Put(ip, val); err != nil {
			log.Printf("[BPF] Failed to add new peer IP: %v", err)
		} else {
			addedCount++
		}
	}

	log.Printf("[BPF] SyncPeers completed. Removed: %d, Added: %d, Total Active: %d",
		len(toDelete), addedCount, len(newPeerIPs))

	return nil
}
