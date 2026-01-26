// Package bpf
package bpf

import (
	"fmt"
	"log"
	"runtime"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
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
func NewBpfManager(hostInterface string) (*BpfManager, error) {
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
		EdtHorizonNs: 2 * 1000 * 1000 * 1000, // 2 Seconds
	}

	if err := objs.ConfigMap.Put(&key, &config); err != nil {
		objs.Close()
		return nil, fmt.Errorf("initializing config map: %w", err)
	}

	mgr := &BpfManager{
		objects:  objs,
		programs: make(map[int]*BpfProgram),
	}

	hostLink, err := netlink.LinkByName(hostInterface)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("failed to find host iface: %s: %w", hostInterface, err)
	}
	hostIfIndex := hostLink.Attrs().Index

	speedMbps, err := getInterfaceSpeed(hostInterface)
	var limitBps uint64

	if err != nil || speedMbps == 0 {
		log.Printf("[BPF] Warning: Could not detect speed for %s (err: %v). Using Default 1Gbps.", hostInterface, err)
		speedMbps = 1000 // default: 1Gbps
	} else {
		log.Printf("[BPF] Detected speed for %s: %d Mbps", hostInterface, speedMbps)
	}

	limitBps = (speedMbps * 1000 * 1000) * 90 / 100 // TODO: this shoule be configurable

	ingressCfg := TcIngressConfig{
		LimitBps:   limitBps,
		BurstBytes: 64 * 1024, // 64KB Burst
	}

	key0 := uint32(0)
	if err = objs.IngressConfigMap.Put(&key0, &ingressCfg); err != nil {
		objs.Close()
		return nil, fmt.Errorf("init ingress config: %w", err)
	}

	// initialze
	ingressState := TcIngressState{
		LastUpdated: 0,
		Tokens:      ingressCfg.BurstBytes,
	}
	if err = objs.IngressStateMap.Put(&key0, &ingressState); err != nil {
		objs.Close()
	}

	// attach fq and egress hook
	if err = mgr.ensureFQ(hostLink.Attrs().Index); err != nil {
		objs.Close()
		return nil, fmt.Errorf("failed to ensure fq on eth0: %w", err)
	}
	log.Printf("[BPF] FQ qdisc ensured on host eth0 (Index: %d)", hostLink.Attrs().Index)

	mgr.eth0EgressLink, err = link.AttachTCX(link.TCXOptions{
		Program:   mgr.objects.HandleEth0Egress,
		Interface: hostIfIndex,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach host egress: %w", err)
	}

	log.Printf("[BPF] host eth0 ebpf program attached")

	mgr.eth0IngressLink, err = link.AttachXDP(link.XDPOptions{
		Program:   mgr.objects.HandleXdpIngress,
		Interface: hostIfIndex,
		Flags:     link.XDPDriverMode,
	})
	// Fallback to GenericMode
	if err != nil {
		fmt.Printf("DriverMode failed, falling back to GenericMode: %v\n", err)

		mgr.eth0IngressLink, err = link.AttachXDP(link.XDPOptions{
			Program:   mgr.objects.HandleXdpIngress,
			Interface: hostIfIndex,
			Flags:     link.XDPGenericMode,
		})
	}
	if err != nil {
		log.Printf("[BPF] Critical: Failed to attach XDP: %v. Ingress protection disabled.", err)
		objs.Close()
		return nil, err
	} else {
		log.Printf("[BPF] XDP Ingress Protection attached to %s (Limit: %d bps)", hostInterface, limitBps)
	}

	return mgr, nil
}

// AddPod sets up traffic control for a pod.
// It attaches BPF programs to BOTH the Host Veth (for download) and Pod Veth (for upload).
func (m *BpfManager) AddPod(podName string, hostIfIndex int, nsHandle netns.NsHandle) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 1. Check if already exists
	if _, ok := m.programs[hostIfIndex]; ok {
		return nil // Already managed
	}

	log.Printf("[BPF] Setting up Pod %s (HostIfIndex: %d)", podName, hostIfIndex)

	prog := &BpfProgram{
		podName:     podName,
		hostIfIndex: hostIfIndex,
		netnsHandle: nsHandle,
	}

	// ==========================================
	// Step 1: Host Side Configuration (Download)
	// ==========================================

	// Ensure FQ on Host Veth
	if err := m.ensureFQ(hostIfIndex); err != nil {
		return fmt.Errorf("host fq: %w", err)
	}

	// Attach EDT to Host Egress (Controls traffic Host -> Pod)
	hostLink, err := link.AttachTCX(link.TCXOptions{
		Program:   m.objects.HandleEdtDownload,
		Interface: hostIfIndex,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return fmt.Errorf("attach host egress: %w", err)
	}
	prog.hostEgressLink = hostLink

	// Initialize Download State Map (Key: HostIfIndex)
	idxHost := uint32(hostIfIndex)
	initEdtState := TcEdtState{}
	if err = m.objects.EdtDownloadStateMap.Update(&idxHost, &initEdtState, ebpf.UpdateAny); err != nil {
		hostLink.Close()
		return fmt.Errorf("init download state: %w", err)
	}

	// ==========================================
	// Step 2: Pod Side Configuration (Upload)
	// ==========================================

	// We utilize a helper function to safely switch namespaces and perform setup
	podIfIndex, podLink, err := m.setupPodEgress(nsHandle)
	if err != nil {
		// Cleanup host link if pod setup fails
		hostLink.Close()
		return fmt.Errorf("pod side setup failed: %w", err)
	}

	prog.podIfIndex = podIfIndex
	prog.podEgressLink = podLink

	// Initialize Upload State Map (Key: PodIfIndex)
	// Even though the map is on the host, the key logic relies on what the BPF program sees (PodIfIndex)
	idxPod := uint32(prog.podIfIndex)
	if err := m.objects.EdtUploadStateMap.Update(&idxPod, &initEdtState, ebpf.UpdateAny); err != nil {
		hostLink.Close()
		prog.podEgressLink.Close()
		return fmt.Errorf("init upload state: %w", err)
	}

	m.programs[hostIfIndex] = prog
	return nil
}

// setupPodEgress handles the namespace switching logic.
// It returns the pod's interface index and the attached link.
func (m *BpfManager) setupPodEgress(podNsHandle netns.NsHandle) (int, link.Link, error) {
	// 1. Lock the OS Thread.
	// This ensures that the runtime doesn't schedule this goroutine to another thread
	// while we are messing with the namespace.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// 2. Save the current (Host) Netns
	hostNs, err := netns.Get()
	if err != nil {
		return 0, nil, fmt.Errorf("failed to get current netns: %w", err)
	}
	// Important: Close the host handle when done to avoid FD leaks
	defer hostNs.Close()

	// 3. Switch to Pod Netns
	if err = netns.Set(podNsHandle); err != nil {
		return 0, nil, fmt.Errorf("failed to enter pod netns: %w", err)
	}

	// 4. DEFER: Restore Host Netns
	// This ensures we ALWAYS go back, even if the code below panics or errors.
	defer func() {
		if err = netns.Set(hostNs); err != nil {
			// If we fail to restore, this thread is corrupted.
			// In a critical system, we might panic here, but logging is minimum.
			log.Printf("[CRITICAL] Failed to restore host netns: %v", err)
		}
	}()

	// =====================================
	// Logic executing INSIDE the Pod Netns
	// =====================================

	// A. Find the default interface (eth0)
	links, err := netlink.LinkList()
	if err != nil {
		return 0, nil, fmt.Errorf("list links in pod: %w", err)
	}

	var targetLink netlink.Link
	for _, l := range links {
		// Pick the first non-loopback interface
		if l.Attrs().Name != "lo" {
			targetLink = l
			break
		}
	}
	if targetLink == nil {
		return 0, nil, fmt.Errorf("no suitable interface (eth0) found in pod")
	}

	podIfIndex := targetLink.Attrs().Index

	// B. Ensure FQ on Pod Interface
	// Since we are in the Pod NS, netlink calls operate on Pod objects.
	if err = m.ensureFQ(podIfIndex); err != nil {
		return 0, nil, fmt.Errorf("pod fq: %w", err)
	}

	// C. Attach EDT to Pod Egress
	// AttachTCX will attach to the interface in the CURRENT namespace.
	ulLink, err := link.AttachTCX(link.TCXOptions{
		Program:   m.objects.HandleEdtUpload,
		Interface: podIfIndex,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return 0, nil, fmt.Errorf("attach pod egress: %w", err)
	}

	// Success. The link object is returned and valid even after we switch back.
	return podIfIndex, ulLink, nil
}

// UpdateRule updates the bandwidth limits for a pod.
// uploadBytes: Limit for Pod -> Host
// downloadBytes: Limit for Host -> Pod
func (m *BpfManager) UpdateRule(hostIfIndex int, uploadRateBits uint64, downloadRateBits uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	prog, ok := m.programs[hostIfIndex]
	if !ok {
		return fmt.Errorf("pod not found for ifindex %d", hostIfIndex)
	}

	// 1. Update Download Rule (Key: HostIfIndex)
	// The Host BPF program looks up using its own ifindex
	keyHost := uint32(hostIfIndex)
	rateCfgDown := TcIoRate{
		RateDownload: downloadRateBits,
		RateUpload:   0, // Unused by download prog
	}
	if err := m.objects.RateMap.Update(&keyHost, &rateCfgDown, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update download rate: %w", err)
	}

	// 2. Update Upload Rule (Key: PodIfIndex)
	// The Pod BPF program looks up using the pod's internal ifindex
	keyPod := uint32(prog.podIfIndex)
	rateCfgUp := TcIoRate{
		RateDownload: 0, // Unused by upload prog
		RateUpload:   uploadRateBits,
	}
	if err := m.objects.RateMap.Update(&keyPod, &rateCfgUp, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update upload rate: %w", err)
	}

	log.Printf("[BPF] Updated Rules for Pod %s: UL=%d Bps, DL=%d Bps", prog.podName, uploadRateBits, downloadRateBits)
	return nil
}

// RemovePod cleans up the maps and detaches programs.
func (m *BpfManager) RemovePod(hostIfIndex int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	prog, ok := m.programs[hostIfIndex]
	if !ok {
		return nil
	}

	// Close links
	// Note: Closing the link detaches the BPF program.
	if prog.hostEgressLink != nil {
		prog.hostEgressLink.Close()
	}
	if prog.podEgressLink != nil {
		prog.podEgressLink.Close()
	}

	// Cleanup Maps
	keyHost := uint32(hostIfIndex)
	keyPod := uint32(prog.podIfIndex)

	// Best effort cleanup
	_ = m.objects.RateMap.Delete(&keyHost)
	_ = m.objects.RateMap.Delete(&keyPod)

	_ = m.objects.EdtDownloadStateMap.Delete(&keyHost)
	_ = m.objects.EdtUploadStateMap.Delete(&keyPod)

	delete(m.programs, hostIfIndex)
	log.Printf("[BPF] Removed Pod %s resources", prog.podName)
	return nil
}

// Close cleans up the BPF objects from the kernel.
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

// AddPeer adds a simulation peer IP to the whitelist map.
// ipStr: IPv4 address string (e.g., "10.244.1.5")
func (m *BpfManager) AddPeer(ipStr string) error {
	ipUint, err := ipToUint32(ipStr)
	if err != nil {
		return err
	}

	val := uint8(1)
	// Key: IPv4 address (Network Byte Order/Big Endian)
	if err := m.objects.SimulationPeersMap.Put(ipUint, val); err != nil {
		return fmt.Errorf("failed to add peer ip %s: %w", ipStr, err)
	}

	// log.Printf("[BPF] Peer Added: %s", ipStr) // Optional: avoid spamming logs
	return nil
}

// RemovePeer removes a simulation peer IP from the whitelist map.
func (m *BpfManager) RemovePeer(ipStr string) error {
	ipUint, err := ipToUint32(ipStr)
	if err != nil {
		return err
	}

	if err := m.objects.SimulationPeersMap.Delete(ipUint); err != nil {
		// Ignore "key not found" errors
		if err != ebpf.ErrKeyNotExist {
			return fmt.Errorf("failed to remove peer ip %s: %w", ipStr, err)
		}
	}

	m.objects.SimulationPeersMap.Iterate()

	log.Printf("[BPF] Peer Removed: %s", ipStr)
	return nil
}

// GetPeers returns a list of all IP addresses currently in the simulation_peers_map.
// This is primarily used for debugging and E2E testing.
func (m *BpfManager) GetPeers() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var (
		key uint32
		val uint8
		ips []string
	)

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
