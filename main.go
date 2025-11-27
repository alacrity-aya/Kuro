package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"kuro/gen"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type rateConfig struct {
	RateLimitBps uint64
	BurstBytes   uint32
	_            uint32
}

type FlowCounter struct {
	AcceptedBytes   uint64
	DroppedBytes    uint64
	AcceptedPackets uint64
	DroppedPackets  uint64
}

func printStats(m *ebpf.Map, key uint32, label string) {
	var values []FlowCounter
	if err := m.Lookup(key, &values); err != nil {
		log.Printf("Error reading stats for %s: %v", label, err)
		return
	}

	var total FlowCounter
	for _, v := range values {
		total.AcceptedBytes += v.AcceptedBytes
		total.DroppedBytes += v.DroppedBytes
		total.AcceptedPackets += v.AcceptedPackets
		total.DroppedPackets += v.DroppedPackets
	}

	log.Printf("[%s] Accept: %d pkts (%d bytes) | Drop: %d pkts (%d bytes)",
		label, total.AcceptedPackets, total.AcceptedBytes, total.DroppedPackets, total.DroppedBytes)
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Removing memlock rlimit failed: %v", err)
	}

	var objs gen.TcObjects

	if err := gen.LoadTcObjects(&objs, nil); err != nil {
		log.Fatalf("load objects: %v", err)
	}
	defer objs.Close()
	log.Println("TC gen program loaded successfully")

	log.Println("Initializing rate limit configurations...")

	simConfig := rateConfig{
		RateLimitBps: 10 * 1024 * 1024, // 10 Mbps
		BurstBytes:   100 * 1024,       // 100 KB Burst
	}
	if err := objs.RateConfigMap.Update(uint32(0), simConfig, ebpf.UpdateAny); err != nil {
		log.Fatalf("Failed to update simulation config: %v", err)
	}

	otherConfig := rateConfig{
		RateLimitBps: 990 * 1024 * 1024, // 990 Mbps
		BurstBytes:   1 * 1024 * 1024,   // 1 MB Burst
	}
	if err := objs.RateConfigMap.Update(uint32(1), otherConfig, ebpf.UpdateAny); err != nil {
		log.Fatalf("Failed to update other traffic config: %v", err)
	}

	log.Printf("Rate limits set: Simulation=%d bps, Other=%d bps", simConfig.RateLimitBps, otherConfig.RateLimitBps)

	ifaceName := "vethe5f555c"
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %v: %v", ifaceName, err)
	}
	log.Printf("iface = %v", iface)

	l, err := link.AttachTCX(link.TCXOptions{Interface: iface.Index, Program: objs.SimTbfEgress, Attach: ebpf.AttachTCXEgress})
	if err != nil {
		log.Fatalf("could not attach TCX program: %s", err)
	}
	defer l.Close()

	log.Printf("Successfully attached eBPF program to %s (index %d)", iface.Name, iface.Index)
	log.Println("Running... Press Ctrl+C to exit.")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			// fmt.Print("\033[H\033[2J")
			log.Println("----- Traffic Statistics -----")
			printStats(objs.FlowStats, 0, "Simulation (Port 8888)")
			printStats(objs.FlowStats, 1, "Other Traffic         ")
		}
	}()

	<-stop
	log.Println("Exiting and cleaning up...")
}
