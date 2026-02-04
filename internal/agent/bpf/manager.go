// Package bpf
package bpf

import (
	"fmt"
	"log"
	"math"
	"runtime"
	"sync"

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

type NetworkPolicyConfig struct {
	BandwidthLimit    uint64 // bps (0 = Default)
	QueueDepthNs      uint64 // ns (0 = Global)
	BaseLatencyNs     uint64 // ns
	JitterNs          uint64 // ns
	CorruptionRatePpm uint32 // ppm (0-1,000,000)
}

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

	// Stores the IP address, used for cleaning up IP-based rules
	podIP string

	// Records the current active Destination rules where this Pod is the Source
	// Key: DstIP, Value: PolicyConfig (or simply true to indicate existence)
	// This allows us to traverse this map and delete entries in the topology_policy_map during RemovePod
	activePolicies map[string]*NetworkPolicyConfig

	// Caches the current bandwidth configuration, used for the Get API
	currentRate *TcIoRate
}

// NewBpfManager loads the BPF programs and initializes global configurations.
func NewBpfManager() (*BpfManager, error) {
	log.Println("[BPF] Starting NewBpfManager...")

	objs := &TcObjects{}
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSizeStart: 64 * 1024 * 1024,
		},
	}

	log.Println("[BPF] Loading TC Objects from ELF...")
	if err := LoadTcObjects(objs, opts); err != nil {
		log.Printf("[BPF] ERROR: Failed to load TC objects: %v", err)
		return nil, fmt.Errorf("loading tc objects: %w", err)
	}
	log.Println("[BPF] TC Objects loaded successfully.")

	// Initialize Global Config
	key := uint32(0)
	config := TcGlobalConfig{
		EdtHorizonNs: 500 * 1000 * 1000, // 500 ms default horizon
	}

	log.Printf("[BPF] Initializing ConfigMap with EdtHorizonNs: %d", config.EdtHorizonNs)
	if err := objs.ConfigMap.Put(&key, &config); err != nil {
		objs.Close()
		log.Printf("[BPF] ERROR: Failed to initialize config map: %v", err)
		return nil, fmt.Errorf("initializing config map: %w", err)
	}

	mgr := &BpfManager{
		objects:  objs,
		programs: make(map[int]*BpfProgram),
	}

	log.Println("[BPF] BpfManager initialized successfully.")
	return mgr, nil
}

// AttachNICEgress attaches the eth0 egress program (Global Sys Latency Enforcer)
func (m *BpfManager) AttachNICEgress(hostInterface string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Printf("[BPF] AttachNICEgress: Target Interface=%s", hostInterface)

	hostLink, err := netlink.LinkByName(hostInterface)
	if err != nil {
		log.Printf("[BPF] ERROR: Interface %s not found: %v", hostInterface, err)
		return fmt.Errorf("failed to find host iface %s: %w", hostInterface, err)
	}
	hostIfIndex := hostLink.Attrs().Index
	log.Printf("[BPF] Found host interface %s, Index=%d", hostInterface, hostIfIndex)

	// Ensure FQ qdisc is present for EDT to work
	log.Printf("[BPF] Ensuring FQ qdisc on interface index %d", hostIfIndex)
	if err = m.ensureFQ(hostIfIndex, 0); err != nil {
		log.Printf("[BPF] ERROR: Failed to ensure FQ on %s: %v", hostInterface, err)
		return fmt.Errorf("failed to ensure fq on %s: %w", hostInterface, err)
	}

	// Detach existing if any (simplistic approach)
	if m.eth0EgressLink != nil {
		log.Println("[BPF] Closing existing eth0 egress link...")
		m.eth0EgressLink.Close()
	}

	log.Println("[BPF] Attaching TCX Egress program to eth0...")
	m.eth0EgressLink, err = link.AttachTCX(link.TCXOptions{
		Program:   m.objects.HandleEth0Egress,
		Interface: hostIfIndex,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Printf("[BPF] ERROR: Failed to attach host egress: %v", err)
		return fmt.Errorf("attach host egress: %w", err)
	}
	log.Println("[BPF] AttachNICEgress completed successfully.")
	return nil
}

// AttachIngressProtection attaches the XDP program for Sys traffic rate limiting
func (m *BpfManager) AttachIngressProtection(hostInterface string, limitBps uint64, burstBytes uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Printf("[BPF] AttachIngressProtection: Interface=%s, LimitBps=%d, BurstBytes=%d", hostInterface, limitBps, burstBytes)

	// Default limit if 0
	if limitBps == 0 {
		speedMbps, err := getInterfaceSpeed(hostInterface)
		if err != nil || speedMbps == 0 {
			log.Printf("[BPF] Warning: Could not detect speed for %s (err=%v), assuming 1Gbps", hostInterface, err)
			speedMbps = 1000 // Assume 1Gbps
		}
		// Limit Sys traffic to 90% of physical capacity
		limitBps = (speedMbps * 1000 * 1000) * 90 / 100
		log.Printf("[BPF] Auto-configured LimitBps to %d (90%% of %d Mbps)", limitBps, speedMbps)
	}
	if burstBytes == 0 {
		burstBytes = 100 * 1024 // 100KB default burst
		log.Printf("[BPF] Auto-configured BurstBytes to default %d", burstBytes)
	}

	hostLink, err := netlink.LinkByName(hostInterface)
	if err != nil {
		log.Printf("[BPF] ERROR: Interface %s not found: %v", hostInterface, err)
		return fmt.Errorf("failed to find host iface %s: %w", hostInterface, err)
	}
	hostIfIndex := hostLink.Attrs().Index

	// Calculate Cost & Burst for Ingress Map
	costPerByteScaled := bpsToScaledCost(limitBps)
	burstNs := (burstBytes * 8 * NsecPerSec) / limitBps

	log.Printf("[BPF] Ingress Calc: CostScaled=%d, BurstNs=%d", costPerByteScaled, burstNs)

	ingressCfg := TcIngressConfig{
		CostPerByteNsScaled: costPerByteScaled,
		BurstNs:             burstNs,
	}

	key0 := uint32(0)
	if err = m.objects.IngressConfigMap.Put(&key0, &ingressCfg); err != nil {
		log.Printf("[BPF] ERROR: Failed to update IngressConfigMap: %v", err)
		return fmt.Errorf("update ingress config: %w", err)
	}

	// Initialize Ingress State
	ingressState := TcIngressState{
		LastUpdated: 0,
		TokensNs:    burstNs,
	}
	if err = m.objects.IngressStateMap.Put(&key0, &ingressState); err != nil {
		log.Printf("[BPF] ERROR: Failed to initialize IngressStateMap: %v", err)
		return fmt.Errorf("init ingress state: %w", err)
	}

	if m.eth0IngressLink != nil {
		log.Println("[BPF] Closing existing eth0 ingress link...")
		m.eth0IngressLink.Close()
	}

	log.Println("[BPF] Attempting to attach XDP (Driver Mode)...")
	// Try XDP Driver Mode first, then Generic
	m.eth0IngressLink, err = link.AttachXDP(link.XDPOptions{
		Program:   m.objects.HandleXdpIngress,
		Interface: hostIfIndex,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		log.Printf("[BPF] Driver XDP failed (%v), trying Generic Mode...", err)
		m.eth0IngressLink, err = link.AttachXDP(link.XDPOptions{
			Program:   m.objects.HandleXdpIngress,
			Interface: hostIfIndex,
			Flags:     link.XDPGenericMode,
		})
	}

	if err != nil {
		log.Printf("[BPF] ERROR: Failed to attach XDP (Driver and Generic): %v", err)
		return fmt.Errorf("attach xdp: %w", err)
	}

	log.Println("[BPF] Ingress Protection attached successfully.")
	return nil
}

// EnsurePodAttached ensures that the BPF programs are attached to the Pod's interface.
// This function is Idempotent: if the pod is already managed, it returns nil immediately.
// It effectively separates "Infrastructure Setup" from "Policy Configuration".
func (m *BpfManager) EnsurePodAttached(podName, podIP string, hostIfIndex int, nsHandle netns.NsHandle) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if prog, ok := m.programs[hostIfIndex]; ok {
		log.Printf("[BPF] Pod %s (Index: %d) already attached. Skipping infra setup.", podName, hostIfIndex)

		if prog.podIP != podIP {
			log.Printf("[BPF] Warning: Pod %s IP changed %s -> %s", podName, prog.podIP, podIP)
			prog.podIP = podIP
		}
		return nil
	}

	log.Printf("[BPF] EnsurePodAttached: New Pod detected. Name=%s, HostIfIndex=%d", podName, hostIfIndex)

	if hostIfIndex >= MaxIfIndexCap {
		return fmt.Errorf("hostIfIndex %d exceeds capacity %d", hostIfIndex, MaxIfIndexCap)
	}

	prog := &BpfProgram{
		podName:        podName,
		podIP:          podIP,
		hostIfIndex:    hostIfIndex,
		netnsHandle:    nsHandle,
		activePolicies: make(map[string]*NetworkPolicyConfig),
	}

	// ==========================================
	// 1. Host Side Setup (Download Control)
	// ==========================================

	// Ensure FQ
	if err := m.ensureFQ(hostIfIndex, 0); err != nil {
		return fmt.Errorf("host fq: %w", err)
	}

	// Attach handle_edt_download
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

	// ==========================================
	// 2. Pod Side Setup (Upload Control)
	// ==========================================

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

	// ==========================================
	// 3. Initialize Metrics & Rate Defaults
	// ==========================================

	// init Metrics Map
	zeroStats := make([]TcPodStats, runtime.NumCPU())
	key := uint32(hostIfIndex)
	_ = m.objects.MetricsMap.Put(&key, zeroStats)

	// init Latency Map
	zeroHist := make([]TcLatencyHist, runtime.NumCPU())
	_ = m.objects.LatencyMap.Put(&key, zeroHist)

	zeroRate := TcIoRate{}
	_ = m.objects.RateMap.Update(&key, &zeroRate, ebpf.UpdateAny) // Host Key
	keyPod := uint32(prog.podIfIndex)
	_ = m.objects.RateMap.Update(&keyPod, &zeroRate, ebpf.UpdateAny) // Pod Key

	m.programs[hostIfIndex] = prog
	log.Printf("[BPF] Pod %s attached successfully (Infrastructure Ready).", podName)
	return nil
}

// AddPod configures eBPF for a new simulation Pod
func (m *BpfManager) AddPod(podName string, hostIfIndex int, nsHandle netns.NsHandle) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Printf("[BPF] AddPod: Name=%s, HostIfIndex=%d", podName, hostIfIndex)

	if hostIfIndex >= MaxIfIndexCap {
		log.Printf("[BPF] ERROR: HostIfIndex %d exceeds capacity %d", hostIfIndex, MaxIfIndexCap)
		return fmt.Errorf("ifindex too large")
	}

	if _, ok := m.programs[hostIfIndex]; ok {
		log.Printf("[BPF] Pod with index %d already managed, skipping.", hostIfIndex)
		return nil // Already added
	}

	prog := &BpfProgram{
		podName:     podName,
		hostIfIndex: hostIfIndex,
		netnsHandle: nsHandle,
	}

	// 1. Host Side Setup (Download Control)
	log.Println("[BPF] Setting up Host Side (Download Control)...")
	// Ensure FQ
	if err := m.ensureFQ(hostIfIndex, 0); err != nil {
		log.Printf("[BPF] ERROR: Failed to ensure FQ on host veth: %v", err)
		return fmt.Errorf("host fq: %w", err)
	}

	// Attach handle_edt_download to Host Veth Egress
	log.Println("[BPF] Attaching HandleEdtDownload to Host Egress...")
	hostLink, err := link.AttachTCX(link.TCXOptions{
		Program:   m.objects.HandleEdtDownload,
		Interface: hostIfIndex,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Printf("[BPF] ERROR: Failed to attach host egress program: %v", err)
		return fmt.Errorf("attach host egress: %w", err)
	}
	prog.hostEgressLink = hostLink

	// Init State Maps for Download (Sys=Even, Sim=Odd)
	initEdtState := TcEdtState{}
	keyHostSys := uint32(hostIfIndex * 2)
	keyHostSim := uint32(hostIfIndex*2 + 1)

	log.Printf("[BPF] Initializing Download State Map (Keys: Sys=%d, Sim=%d)", keyHostSys, keyHostSim)

	if err = m.objects.EdtDownloadStateMap.Update(&keyHostSys, &initEdtState, ebpf.UpdateAny); err != nil {
		hostLink.Close()
		log.Printf("[BPF] ERROR: Init Download Sys state failed: %v", err)
		return fmt.Errorf("init download sys state: %w", err)
	}
	if err = m.objects.EdtDownloadStateMap.Update(&keyHostSim, &initEdtState, ebpf.UpdateAny); err != nil {
		hostLink.Close()
		log.Printf("[BPF] ERROR: Init Download Sim state failed: %v", err)
		return fmt.Errorf("init download sim state: %w", err)
	}

	// 2. Pod Side Setup (Upload Control)
	log.Println("[BPF] Entering Pod Namespace for Upload Control setup...")
	podIfIndex, podLink, err := m.setupPodEgress(nsHandle)
	if err != nil {
		hostLink.Close()
		log.Printf("[BPF] ERROR: Pod side setup failed: %v", err)
		return fmt.Errorf("pod side setup failed: %w", err)
	}
	log.Printf("[BPF] Pod Side Setup done. PodIfIndex=%d", podIfIndex)

	prog.podIfIndex = podIfIndex
	prog.podEgressLink = podLink

	// Init State Maps for Upload (Sys=Even, Sim=Odd)
	keyPodSys := uint32(prog.podIfIndex * 2)
	keyPodSim := uint32(prog.podIfIndex*2 + 1)

	log.Printf("[BPF] Initializing Upload State Map (Keys: Sys=%d, Sim=%d)", keyPodSys, keyPodSim)

	if err := m.objects.EdtUploadStateMap.Update(&keyPodSys, &initEdtState, ebpf.UpdateAny); err != nil {
		hostLink.Close()
		prog.podEgressLink.Close()
		log.Printf("[BPF] ERROR: Init Upload Sys state failed: %v", err)
		return fmt.Errorf("init upload sys state: %w", err)
	}
	if err := m.objects.EdtUploadStateMap.Update(&keyPodSim, &initEdtState, ebpf.UpdateAny); err != nil {
		hostLink.Close()
		prog.podEgressLink.Close()
		log.Printf("[BPF] ERROR: Init Upload Sim state failed: %v", err)
		return fmt.Errorf("init upload sim state: %w", err)
	}

	// 3. Initialize Metrics & Latency Maps (PerCPU)
	log.Println("[BPF] Initializing Metrics and Latency Maps...")
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
	log.Printf("[BPF] AddPod %s completed successfully.", podName)
	return nil
}

// setupPodEgress enters the Pod namespace and attaches the upload program
func (m *BpfManager) setupPodEgress(podNsHandle netns.NsHandle) (int, link.Link, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	log.Println("[BPF] [NsSwitch] Saving current host netns...")
	hostNs, err := netns.Get()
	if err != nil {
		return 0, nil, fmt.Errorf("failed to get current netns: %w", err)
	}
	defer hostNs.Close()

	log.Println("[BPF] [NsSwitch] Switching to pod netns...")
	if err = netns.Set(podNsHandle); err != nil {
		return 0, nil, fmt.Errorf("failed to enter pod netns: %w", err)
	}

	defer func() {
		log.Println("[BPF] [NsSwitch] Restoring host netns...")
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
			log.Printf("[BPF] Found target interface inside pod: %s (Index: %d)", l.Attrs().Name, l.Attrs().Index)
			break
		}
	}
	if targetLink == nil {
		return 0, nil, fmt.Errorf("no suitable interface (eth0) found in pod")
	}

	podIfIndex := targetLink.Attrs().Index

	// Ensure FQ inside Pod
	log.Printf("[BPF] Ensuring FQ inside pod on index %d", podIfIndex)
	if err = m.ensureFQ(podIfIndex, 0); err != nil {
		return 0, nil, fmt.Errorf("pod fq: %w", err)
	}

	log.Println("[BPF] Attaching HandleEdtUpload to Pod Egress...")
	ulLink, err := link.AttachTCX(link.TCXOptions{
		Program:   m.objects.HandleEdtUpload,
		Interface: podIfIndex,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Printf("[BPF] ERROR: Failed to attach pod egress: %v", err)
		return 0, nil, fmt.Errorf("attach pod egress: %w", err)
	}

	return podIfIndex, ulLink, nil
}

// UpdateRule updates the bandwidth limits (Sim & Sys) for a specific Pod.
// This sets the base rates in the RateMap.
func (m *BpfManager) UpdateRule(hostIfIndex int, simUploadBps, simDownloadBps, sysUploadBps, sysDownloadBps uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Printf("[BPF] UpdateRule: HostIfIndex=%d. SimUL=%d, SimDL=%d, SysUL=%d, SysDL=%d",
		hostIfIndex, simUploadBps, simDownloadBps, sysUploadBps, sysDownloadBps)

	prog, ok := m.programs[hostIfIndex]
	if !ok {
		log.Printf("[BPF] ERROR: Pod with HostIfIndex %d not found", hostIfIndex)
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

	log.Printf("[BPF] Updating Host Rate Map (Key=%d) DownCosts: Sim=%d, Sys=%d",
		keyHost, rateCfgDown.CostPerByteSimDownload, rateCfgDown.CostPerByteSysDownload)

	if err := m.objects.RateMap.Update(&keyHost, &rateCfgDown, ebpf.UpdateAny); err != nil {
		log.Printf("[BPF] ERROR: Failed to update Host Rate Map: %v", err)
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

	log.Printf("[BPF] Updating Pod Rate Map (Key=%d) UpCosts: Sim=%d, Sys=%d",
		keyPod, rateCfgUp.CostPerByteSimUpload, rateCfgUp.CostPerByteSysUpload)

	if err := m.objects.RateMap.Update(&keyPod, &rateCfgUp, ebpf.UpdateAny); err != nil {
		log.Printf("[BPF] ERROR: Failed to update Pod Rate Map: %v", err)
		return fmt.Errorf("update upload rate: %w", err)
	}

	return nil
}

// SetPolicy sets or removes a specific physical link policy between two IPs.
// srcIP: The source IP (should match the Pod managed by this call context, or generic)
// dstIP: The destination IP
// policy: The policy struct. If nil, the policy is deleted (reverting to System Traffic).
func (m *BpfManager) SetPolicy(srcIP string, dstIP string, config *NetworkPolicyConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Printf("[BPF] SetPolicy: Src=%s -> Dst=%s", srcIP, dstIP)

	sIPUint, err := ipToUint32(srcIP)
	if err != nil {
		log.Printf("[BPF] ERROR: Invalid SrcIP %s: %v", srcIP, err)
		return err
	}
	dIPUint, err := ipToUint32(dstIP)
	if err != nil {
		log.Printf("[BPF] ERROR: Invalid DstIP %s: %v", dstIP, err)
		return err
	}

	key := TcPolicyKey{SrcIp: sIPUint, DstIp: dIPUint}

	var prog *BpfProgram
	for _, p := range m.programs {
		if p.podIP == srcIP {
			prog = p
			break
		}
	}

	if prog != nil {
		if config == nil {
			delete(prog.activePolicies, dstIP)
		} else {
			prog.activePolicies[dstIP] = config
		}
	} else {
		log.Printf("[BPF] Note: Setting policy for unmanaged/external SrcIP: %s", srcIP)
	}

	if config == nil {
		log.Printf("[BPF] Config is nil, deleting policy for %s->%s", srcIP, dstIP)
		if err := m.objects.TopologyPolicyMap.Delete(key); err != nil {
			if err != ebpf.ErrKeyNotExist {
				log.Printf("[BPF] ERROR: Failed to delete policy: %v", err)
				return fmt.Errorf("failed to delete policy: %w", err)
			}
			log.Println("[BPF] Policy did not exist, nothing to delete.")
		}
		return nil
	}

	// === Conversion Logic (User -> Kernel) ===
	policyMapVal := TcLinkPolicy{
		QueueDepthNs:  config.QueueDepthNs,
		BaseLatencyNs: config.BaseLatencyNs,
		JitterNs:      config.JitterNs,
		Padding:       0,
	}

	// 1. Convert Bandwidth (bps) -> Cost
	if config.BandwidthLimit > 0 {
		policyMapVal.CostPerByteScaled = bpsToScaledCost(config.BandwidthLimit)
	} else {
		policyMapVal.CostPerByteScaled = 0 // Signal kernel to use default
	}

	// 2. Convert PPM -> Threshold
	// Threshold = (ppm / 1,000,000) * UINT32_MAX
	if config.CorruptionRatePpm > 0 {
		// Use uint64 to prevent overflow during multiplication
		// MaxUint32 is 4,294,967,295
		val := (uint64(config.CorruptionRatePpm) * uint64(math.MaxUint32)) / 1_000_000
		policyMapVal.CorruptionThreshold = uint32(val)
	} else {
		policyMapVal.CorruptionThreshold = 0
	}

	log.Printf("[BPF] Applying Policy: Latency=%d, Jitter=%d, Cost=%d, CorruptThresh=%d",
		policyMapVal.BaseLatencyNs, policyMapVal.JitterNs, policyMapVal.CostPerByteScaled, policyMapVal.CorruptionThreshold)

	if err := m.objects.TopologyPolicyMap.Put(key, &policyMapVal); err != nil {
		log.Printf("[BPF] ERROR: Failed to put policy map: %v", err)
		return fmt.Errorf("failed to put policy: %w", err)
	}

	return nil
}

func (m *BpfManager) RemovePod(hostIfIndex int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Printf("[BPF] RemovePod: HostIfIndex=%d", hostIfIndex)

	prog, ok := m.programs[hostIfIndex]
	if !ok {
		return nil
	}

	if len(prog.activePolicies) > 0 {
		log.Printf("[BPF] Cleaning up %d active link policies...", len(prog.activePolicies))
		srcIPUint, _ := ipToUint32(prog.podIP)

		for dstIP := range prog.activePolicies {
			dstIPUint, _ := ipToUint32(dstIP)
			key := TcPolicyKey{SrcIp: srcIPUint, DstIp: dstIPUint}

			if err := m.objects.TopologyPolicyMap.Delete(key); err != nil {
				// ignore key not exist
				if err != ebpf.ErrKeyNotExist {
					log.Printf("[BPF] Warn: Failed to delete policy %s->%s: %v", prog.podIP, dstIP, err)
				}
			}
		}
		// remove active policies
		prog.activePolicies = nil
	}

	// Close Links
	if prog.hostEgressLink != nil {
		log.Println("[BPF] Closing Host Egress Link...")
		prog.hostEgressLink.Close()
	}
	if prog.podEgressLink != nil {
		log.Println("[BPF] Closing Pod Egress Link...")
		prog.podEgressLink.Close()
	}

	// Cleanup Maps
	zeroRate := TcIoRate{}
	zeroState := TcEdtState{}

	log.Println("[BPF] Clearing Rate Maps...")
	// Clear Rate Map
	keyHost := uint32(hostIfIndex)
	keyPod := uint32(prog.podIfIndex)
	_ = m.objects.RateMap.Update(&keyHost, &zeroRate, ebpf.UpdateAny)
	_ = m.objects.RateMap.Update(&keyPod, &zeroRate, ebpf.UpdateAny)

	log.Println("[BPF] Clearing EDT State Maps...")
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
	log.Println("[BPF] Clearing Metrics and Latency Maps...")
	_ = m.objects.MetricsMap.Delete(&keyHost)
	_ = m.objects.LatencyMap.Delete(&keyHost)

	delete(m.programs, hostIfIndex)
	log.Println("[BPF] RemovePod completed.")
	return nil
}

func (m *BpfManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Println("[BPF] Closing BpfManager and all links...")

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

	log.Println("[BPF] Closing BPF Objects...")
	return m.objects.Close()
}
