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

	// Initialize Global Config
	key := uint32(0)
	config := TcGlobalConfig{
		EdtHorizonNs: 500 * 1000 * 1000, // 500 ms default horizon
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

// AttachNICEgress attaches the eth0 egress program (Global Sys Latency Enforcer)
func (m *BpfManager) AttachNICEgress(hostInterface string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	hostLink, err := netlink.LinkByName(hostInterface)
	if err != nil {
		return fmt.Errorf("failed to find host iface %s: %w", hostInterface, err)
	}
	hostIfIndex := hostLink.Attrs().Index

	// Ensure FQ qdisc is present for EDT to work
	if err = m.ensureFQ(hostIfIndex, 0); err != nil {
		return fmt.Errorf("failed to ensure fq on %s: %w", hostInterface, err)
	}

	// Detach existing if any (simplistic approach)
	if m.eth0EgressLink != nil {
		m.eth0EgressLink.Close()
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

// AttachIngressProtection attaches the XDP program for Sys traffic rate limiting
func (m *BpfManager) AttachIngressProtection(hostInterface string, limitBps uint64, burstBytes uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Default limit if 0
	if limitBps == 0 {
		speedMbps, err := getInterfaceSpeed(hostInterface)
		if err != nil || speedMbps == 0 {
			speedMbps = 1000 // Assume 1Gbps
		}
		// Limit Sys traffic to 90% of physical capacity
		limitBps = (speedMbps * 1000 * 1000) * 90 / 100
	}
	if burstBytes == 0 {
		burstBytes = 100 * 1024 // 100KB default burst
	}

	hostLink, err := netlink.LinkByName(hostInterface)
	if err != nil {
		return fmt.Errorf("failed to find host iface %s: %w", hostInterface, err)
	}
	hostIfIndex := hostLink.Attrs().Index

	// Calculate Cost & Burst for Ingress Map
	costPerByteScaled := bpsToScaledCost(limitBps)
	burstNs := (burstBytes * 8 * NsecPerSec) / limitBps

	ingressCfg := TcIngressConfig{
		CostPerByteNsScaled: costPerByteScaled,
		BurstNs:             burstNs,
	}

	key0 := uint32(0)
	if err = m.objects.IngressConfigMap.Put(&key0, &ingressCfg); err != nil {
		return fmt.Errorf("update ingress config: %w", err)
	}

	// Initialize Ingress State
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

	// Try XDP Driver Mode first, then Generic
	m.eth0IngressLink, err = link.AttachXDP(link.XDPOptions{
		Program:   m.objects.HandleXdpIngress,
		Interface: hostIfIndex,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		log.Printf("[BPF] Driver XDP failed, trying Generic: %v", err)
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

// AddPod configures eBPF for a new simulation Pod
func (m *BpfManager) AddPod(podName string, hostIfIndex int, nsHandle netns.NsHandle) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if hostIfIndex >= MaxIfIndexCap {
		return fmt.Errorf("ifindex too large")
	}

	if _, ok := m.programs[hostIfIndex]; ok {
		return nil // Already added
	}

	log.Printf("[BPF] Setting up Pod %s (HostIfIndex: %d)", podName, hostIfIndex)

	prog := &BpfProgram{
		podName:     podName,
		hostIfIndex: hostIfIndex,
		netnsHandle: nsHandle,
	}

	// 1. Host Side Setup (Download Control)
	// Ensure FQ
	if err := m.ensureFQ(hostIfIndex, 0); err != nil {
		return fmt.Errorf("host fq: %w", err)
	}

	// Attach handle_edt_download to Host Veth Egress
	hostLink, err := link.AttachTCX(link.TCXOptions{
		Program:   m.objects.HandleEdtDownload,
		Interface: hostIfIndex,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return fmt.Errorf("attach host egress: %w", err)
	}
	prog.hostEgressLink = hostLink

	// Init State Maps for Download (Sys=Even, Sim=Odd)
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

	// 2. Pod Side Setup (Upload Control)
	podIfIndex, podLink, err := m.setupPodEgress(nsHandle)
	if err != nil {
		hostLink.Close()
		return fmt.Errorf("pod side setup failed: %w", err)
	}

	prog.podIfIndex = podIfIndex
	prog.podEgressLink = podLink

	// Init State Maps for Upload (Sys=Even, Sim=Odd)
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

	// 3. Initialize Metrics & Latency Maps (PerCPU)
	zeroStats := make([]TcPodStats, runtime.NumCPU())
	key := uint32(hostIfIndex)
	if err := m.objects.MetricsMap.Put(&key, zeroStats); err != nil {
		log.Printf("[BPF] Warning: Failed to init metrics map for %s: %v", podName, err)
	}

	zeroHist := make([]TcLatencyHist, runtime.NumCPU())
	if err := m.objects.LatencyMap.Put(&key, zeroHist); err != nil {
		log.Printf("[BPF] Warning: Failed to init latency map for %s: %v", podName, err)
	}

	m.programs[hostIfIndex] = prog
	return nil
}

// setupPodEgress enters the Pod namespace and attaches the upload program
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
		// Typically eth0, avoiding loopback
		if l.Attrs().Name != "lo" {
			targetLink = l
			break
		}
	}
	if targetLink == nil {
		return 0, nil, fmt.Errorf("no suitable interface (eth0) found in pod")
	}

	podIfIndex := targetLink.Attrs().Index

	// Ensure FQ inside Pod
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

// UpdateRule updates the bandwidth limits (Sim & Sys) for a specific Pod.
// This sets the base rates in the RateMap.
func (m *BpfManager) UpdateRule(hostIfIndex int, simUploadBps, simDownloadBps, sysUploadBps, sysDownloadBps uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	prog, ok := m.programs[hostIfIndex]
	if !ok {
		return fmt.Errorf("pod not found")
	}

	if hostIfIndex >= MaxIfIndexCap {
		return fmt.Errorf("ifindex %d exceeds max capacity", hostIfIndex)
	}

	// 1. Update Host Side (Download Control)
	// For Download, we primarily use the Sim/Sys Download limits
	keyHost := uint32(hostIfIndex)
	rateCfgDown := TcIoRate{
		CostPerByteSimDownload: bpsToScaledCost(simDownloadBps),
		CostPerByteSysDownload: bpsToScaledCost(sysDownloadBps),
		// Upload fields on Host map entry are generally unused by the Download Hook,
		// but we can zero them or set them symmetrically. Keeping them 0 for clarity.
		CostPerByteSimUpload: 0,
		CostPerByteSysUpload: 0,
	}
	if err := m.objects.RateMap.Update(&keyHost, &rateCfgDown, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update download rate: %w", err)
	}

	// 2. Update Pod Side (Upload Control)
	// For Upload, we primarily use the Sim/Sys Upload limits
	keyPod := uint32(prog.podIfIndex)
	rateCfgUp := TcIoRate{
		CostPerByteSimUpload: bpsToScaledCost(simUploadBps),
		CostPerByteSysUpload: bpsToScaledCost(sysUploadBps),
		// Download fields on Pod map entry are unused by Upload Hook
		CostPerByteSimDownload: 0,
		CostPerByteSysDownload: 0,
	}
	if err := m.objects.RateMap.Update(&keyPod, &rateCfgUp, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update upload rate: %w", err)
	}

	return nil
}

// SetPolicy sets or removes a specific physical link policy between two IPs.
// srcIP: The source IP (should match the Pod managed by this call context, or generic)
// dstIP: The destination IP
// policy: The policy struct. If nil, the policy is deleted (reverting to System Traffic).
func (m *BpfManager) SetPolicy(srcIP string, dstIP string, policy *TcLinkPolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sIpUint, err := ipToUint32(srcIP)
	if err != nil {
		return err
	}
	dIpUint, err := ipToUint32(dstIP)
	if err != nil {
		return err
	}

	// Construct the Composite Key
	key := TcPolicyKey{
		SrcIp: sIpUint,
		DstIp: dIpUint,
	}

	if policy == nil {
		// Delete Policy
		if err := m.objects.TopologyPolicyMap.Delete(key); err != nil {
			if err != ebpf.ErrKeyNotExist {
				return fmt.Errorf("failed to delete policy for %s->%s: %w", srcIP, dstIP, err)
			}
		}
		return nil
	}

	// Add/Update Policy
	if err := m.objects.TopologyPolicyMap.Put(key, policy); err != nil {
		return fmt.Errorf("failed to put policy for %s->%s: %w", srcIP, dstIP, err)
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

	// Close Links
	if prog.hostEgressLink != nil {
		prog.hostEgressLink.Close()
	}
	if prog.podEgressLink != nil {
		prog.podEgressLink.Close()
	}

	// Cleanup Maps
	zeroRate := TcIoRate{}
	zeroState := TcEdtState{}

	// Clear Rate Map
	keyHost := uint32(hostIfIndex)
	keyPod := uint32(prog.podIfIndex)
	_ = m.objects.RateMap.Update(&keyHost, &zeroRate, ebpf.UpdateAny)
	_ = m.objects.RateMap.Update(&keyPod, &zeroRate, ebpf.UpdateAny)

	// Clear State Maps (both Sim and Sys slots)
	keyHostSys := uint32(hostIfIndex * 2)
	keyHostSim := uint32(hostIfIndex*2 + 1)
	_ = m.objects.EdtDownloadStateMap.Update(&keyHostSys, &zeroState, ebpf.UpdateAny)
	_ = m.objects.EdtDownloadStateMap.Update(&keyHostSim, &zeroState, ebpf.UpdateAny)

	keyPodSys := uint32(prog.podIfIndex * 2)
	keyPodSim := uint32(prog.podIfIndex*2 + 1)
	_ = m.objects.EdtUploadStateMap.Update(&keyPodSys, &zeroState, ebpf.UpdateAny)
	_ = m.objects.EdtUploadStateMap.Update(&keyPodSim, &zeroState, ebpf.UpdateAny)

	// Clear Metrics
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

// PodMetricsResult structure for JSON export
type PodMetricsResult struct {
	PodName     string        `json:"pod_name"`
	HostIfIndex int           `json:"host_ifindex"`
	Timestamp   int64         `json:"timestamp"`
	Stats       TcPodStats    `json:"stats"`
	Latency     TcLatencyHist `json:"latency"`
}

func (m *BpfManager) CollectAllMetrics() ([]PodMetricsResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var results []PodMetricsResult

	for ifIndex, prog := range m.programs {
		key := uint32(ifIndex)

		// 1. Collect Flow Stats (PerCPU aggregation)
		var statsPerCPU []TcPodStats
		if err := m.objects.MetricsMap.Lookup(&key, &statsPerCPU); err != nil {
			continue
		}

		var totalStats TcPodStats
		for _, cpuStat := range statsPerCPU {
			// Aggregate fields
			totalStats.SimDownload.Packets += cpuStat.SimDownload.Packets
			totalStats.SimDownload.Bytes += cpuStat.SimDownload.Bytes
			totalStats.SimDownload.DropPackets += cpuStat.SimDownload.DropPackets
			totalStats.SimDownload.DropBytes += cpuStat.SimDownload.DropBytes
			// ... (Repeat for SimUpload, SysDownload, SysUpload)
			totalStats.SimUpload.Packets += cpuStat.SimUpload.Packets
			totalStats.SimUpload.Bytes += cpuStat.SimUpload.Bytes
			totalStats.SimUpload.DropPackets += cpuStat.SimUpload.DropPackets
			totalStats.SimUpload.DropBytes += cpuStat.SimUpload.DropBytes

			totalStats.SysDownload.Packets += cpuStat.SysDownload.Packets
			totalStats.SysDownload.Bytes += cpuStat.SysDownload.Bytes
			totalStats.SysDownload.DropPackets += cpuStat.SysDownload.DropPackets
			totalStats.SysDownload.DropBytes += cpuStat.SysDownload.DropBytes

			totalStats.SysUpload.Packets += cpuStat.SysUpload.Packets
			totalStats.SysUpload.Bytes += cpuStat.SysUpload.Bytes
			totalStats.SysUpload.DropPackets += cpuStat.SysUpload.DropPackets
			totalStats.SysUpload.DropBytes += cpuStat.SysUpload.DropBytes
		}

		// 2. Collect Latency Histogram
		var latHists []TcLatencyHist
		var totalLatency TcLatencyHist
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
