// Package bpf
package bpf

import (
	"fmt"
	"log"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

type BpfManager struct {
	mu      sync.RWMutex
	objects *TcObjects
	links   map[int]*gressLink
}

type gressLink struct {
	ingress link.Link
	egress  link.Link
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
		EdtHorizonNs:  2 * 1000 * 1000 * 1000,
		TbfBurstBytes: 200 * 1024,
	}

	if err := objs.ConfigMap.Put(&key, &config); err != nil {
		objs.Close()
		return nil, fmt.Errorf("initializing config map: %w", err)
	}

	return &BpfManager{
		objects: objs,
		links:   make(map[int]*gressLink),
	}, nil
}

func (m *BpfManager) AddPod(podName string, ifaceIndex int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	linkInfo, err := netlink.LinkByIndex(ifaceIndex)
	if err != nil {
		return fmt.Errorf("failed to find link %d: %w", ifaceIndex, err)
	}

	log.Printf("[BPF] Setting up Pod %s on interface:%s (%d)", linkInfo.Attrs().Name, podName, ifaceIndex)

	if err = m.ensureFQ(ifaceIndex); err != nil {
		return fmt.Errorf("ensure fq: %w", err)
	}

	if _, ok := m.links[ifaceIndex]; !ok {
		m.links[ifaceIndex] = &gressLink{}
	}
	links := m.links[ifaceIndex]

	if links.egress == nil {
		l, err := link.AttachTCX(link.TCXOptions{
			Program:   m.objects.HandleTbfIngress,
			Interface: ifaceIndex,
			Attach:    ebpf.AttachTCXEgress,
		})
		if err != nil {
			return fmt.Errorf("attach egress: %w", err)
		}
		links.egress = l

	}

	if links.ingress == nil {
		l, err := link.AttachTCX(link.TCXOptions{
			Program:   m.objects.HandleEdtEgress,
			Interface: ifaceIndex,
			Attach:    ebpf.AttachTCXIngress,
		})
		if err != nil {
			return fmt.Errorf("attach ingress: %w", err)
		}
		links.ingress = l
	}

	idx := uint32(ifaceIndex)

	initEdt := TcEdtState{}
	if err := m.objects.EdtStateMap.Update(&idx, &initEdt, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("init edt state: %w", err)
	}

	initTbf := TcTbfState{}
	if err := m.objects.TbfStateMap.Update(&idx, &initTbf, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("init tbf state: %w", err)
	}

	return nil
}

func (m *BpfManager) UpdateRule(ifaceIndex int, limitBytes uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	idx := uint32(ifaceIndex)

	if err := m.objects.RateMap.Put(&idx, &limitBytes); err != nil {
		return fmt.Errorf("update rate rule: %w", err)
	}

	log.Printf("[BPF] Rule updated: ifindex %d set to %d bytes/s", ifaceIndex, limitBytes)
	return nil
}

// RemovePod cleans up the maps for a removed Pod.
// Note: The Qdiscs and Filters are automatically removed by the kernel when the interface is deleted.
func (m *BpfManager) RemovePod(podName string, ifaceIndex int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// TODO: remove links

	idx := uint32(ifaceIndex)

	// Best effort cleaning
	_ = m.objects.RateMap.Delete(&idx)
	_ = m.objects.EdtStateMap.Delete(&idx)
	_ = m.objects.TbfStateMap.Delete(&idx)

	log.Printf("[BPF] Cleaned up resources for Pod %s (ifindex %d)", podName, ifaceIndex)
	return nil
}

// Close cleans up the BPF objects from the kernel.
func (m *BpfManager) Close() error {
	for _, program := range m.links {
		program.egress.Close()
		program.ingress.Close()
	}

	return m.objects.Close()
}

// ================= Helpers =================

func (m *BpfManager) removeFQ(ifaceIndex int) error {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifaceIndex,
			Parent:    netlink.HANDLE_ROOT,
		},
		QdiscType: "fq",
	}
	return netlink.QdiscDel(qdisc)
}

// ensureFQ: we use fq to analog delay effect
func (m *BpfManager) ensureFQ(ifaceIndex int) error {
	linkObj, err := netlink.LinkByIndex(ifaceIndex)
	if err != nil {
		return err
	}
	qdiscs, err := netlink.QdiscList(linkObj)
	if err != nil {
		return err
	}

	// if Root Qdisc exists
	for _, q := range qdiscs {
		if q.Attrs().Parent == netlink.HANDLE_ROOT {
			if q.Type() == "fq" {
				return nil
			}
			// delete pfifo_fast, noqueue 先删除
			if err := netlink.QdiscDel(q); err != nil {
				return fmt.Errorf("failed to del existing qdisc %s: %w", q.Type(), err)
			}
			break
		}
	}

	fq := netlink.NewFq(netlink.QdiscAttrs{
		LinkIndex: linkObj.Attrs().Index,
		Parent:    netlink.HANDLE_ROOT,
		Handle:    netlink.MakeHandle(1, 0),
	})
	return netlink.QdiscAdd(fq)
}
