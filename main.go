package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"kuro/gen"
	"kuro/pkg/config"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type rule struct {
	RateLimitBps uint64
	TimeScale    uint64
	BurstBytes   uint32
	Gress        uint8
} // WANRING: align in C

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

var Logger *zap.Logger

func setupLogger(levelStr string) *zap.Logger {
	var level zapcore.Level

	if err := level.Set(strings.ToLower(levelStr)); err != nil {
		log.Printf("Invalid log level '%s' in config.toml. Defaulting to INFO.", levelStr)
		level = zapcore.InfoLevel
	}

	cfg := zap.Config{
		Encoding:         "json",
		Level:            zap.NewAtomicLevelAt(level),
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
		EncoderConfig: zapcore.EncoderConfig{
			MessageKey:    "msg",
			LevelKey:      "level",
			TimeKey:       "ts",
			EncodeTime:    zapcore.ISO8601TimeEncoder,
			EncodeLevel:   zapcore.CapitalLevelEncoder,
			EncodeCaller:  zapcore.ShortCallerEncoder,
			StacktraceKey: "stacktrace",
		},
	}

	logger, err := cfg.Build()
	if err != nil {
		log.Fatalf("Failed to build zap logger: %v", err)
	}
	return logger
}

func LoadConfig() {
	if err := config.LoadConfig("config.toml"); err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	Logger = setupLogger(config.C.Log.Level)
	defer Logger.Sync()

	Logger.Info("Application startup sequence initiated",
		zap.String("iface_name", config.C.Rule.IfaceName),
		zap.String("traffic_type", config.C.Rule.Gress),
	)

	Logger.Debug("Loaded traffic rate limiting rule details",
		zap.String("rate", config.C.Rule.Rate),
		zap.String("time_scale", config.C.Rule.TimeScale),
		zap.Ints("ports_affected", config.C.Rule.Port),
	)
}

func AttachBPFProg() {
	if err := rlimit.RemoveMemlock(); err != nil {
		Logger.Fatal("Removing memlock rlimit failed", zap.Error(err))
	}

	var objs gen.TcObjects

	if err := gen.LoadTcObjects(&objs, nil); err != nil {
		Logger.Fatal("Failed to load eBPF objects", zap.Error(err))
	}
	defer objs.Close()
	Logger.Info("TC gen program loaded successfully")

	Logger.Info("Initializing rate limit configurations")

	simConfig := rule{
		RateLimitBps: 10 * 1024 * 1024,
		BurstBytes:   100 * 1024,
	}
	if err := objs.RateConfigMap.Update(uint32(0), simConfig, ebpf.UpdateAny); err != nil {
		Logger.Fatal("Failed to update simulation config map", zap.Error(err), zap.Uint32("key", 0))
	}

	otherConfig := rule{
		RateLimitBps: 990 * 1024 * 1024,
		BurstBytes:   1 * 1024 * 1024,
	}
	if err := objs.RateConfigMap.Update(uint32(1), otherConfig, ebpf.UpdateAny); err != nil {
		Logger.Fatal("Failed to update other traffic config map", zap.Error(err), zap.Uint32("key", 1))
	}

	Logger.Info("Rate limits set successfully",
		zap.Uint64("sim_rate_bps", simConfig.RateLimitBps),
		zap.Uint64("other_rate_bps", otherConfig.RateLimitBps),
	)

	ifaceName := config.C.Rule.IfaceName
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		Logger.Fatal("Lookup network interface failed", zap.String("iface_name", ifaceName), zap.Error(err))
	}
	Logger.Debug("Network interface looked up", zap.String("iface", iface.Name), zap.Int("index", iface.Index))

	l, err := link.AttachTCX(link.TCXOptions{Interface: iface.Index, Program: objs.Egress, Attach: ebpf.AttachTCXEgress})
	if err != nil {
		Logger.Fatal("Could not attach TCX egress program", zap.String("iface", iface.Name), zap.Error(err))
	}
	defer l.Close()

	l2, err := link.AttachTCX(link.TCXOptions{Interface: iface.Index, Program: objs.Ingress, Attach: ebpf.AttachTCXIngress})
	if err != nil {
		Logger.Fatal("Could not attach TCX ingress program", zap.String("iface", iface.Name), zap.Error(err))
	}
	defer l2.Close()

	Logger.Info("Successfully attached eBPF program", zap.String("iface_name", iface.Name), zap.Int("iface_index", iface.Index))
	Logger.Info("Running... Press Ctrl+C to exit")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			Logger.Info("----- Traffic Statistics -----")
			// printStats(objs.FlowStats, 0, "Simulation (Port 8888)")
			// printStats(objs.FlowStats, 1, "Other Traffic       ")
		}
	}()

	<-stop
	Logger.Info("Exiting and cleaning up")
}

func main() {
	LoadConfig()
	AttachBPFProg()
}
