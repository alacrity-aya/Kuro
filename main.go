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
		zap.String("iface_name", config.C.Rule.Iface),
		zap.String("traffic_type", config.C.Rule.Gress),
	)

	Logger.Debug("Loaded traffic rate limiting rule details",
		zap.Uint64("target_rate_bps", config.C.TargetRateBps),
		zap.Uint64("target_time_ms", config.C.TargetTimeMs),
		zap.Ints("target_ports", config.C.Rule.Target.Ports),
		zap.Uint64("other_rate_bps", config.C.OtherRateBps),
		zap.Uint64("other_time_ms", config.C.OtherTimeMs),
	)
}

// ----------------------------
// Update eBPF map
// ----------------------------
func updateMap(objs *gen.TcObjects) {
	// Key 0 -> Simulation Traffic (Target)
	simRule := gen.TcRule{
		RateLimitBps: config.C.TargetRateBps,
		TimeScaleMs:  config.C.TargetTimeMs,
		BurstBytes:   0,
	}
	if err := objs.RateConfigMap.Update(uint32(0), &simRule, ebpf.UpdateAny); err != nil {
		Logger.Fatal("Failed to update simulation config map", zap.Error(err), zap.Uint32("key", 0))
	}

	// Key 1 -> Other Traffic
	otherRule := gen.TcRule{
		RateLimitBps: config.C.OtherRateBps,
		TimeScaleMs:  config.C.OtherTimeMs,
		BurstBytes:   0,
	}
	if err := objs.RateConfigMap.Update(uint32(1), &otherRule, ebpf.UpdateAny); err != nil {
		Logger.Fatal("Failed to update other traffic config map", zap.Error(err), zap.Uint32("key", 1))
	}

	for _, p := range config.C.Rule.Target.Ports {
		key := gen.TcPortKey{
			Port: uint16(p),
		}
		value := uint8(1) // 1 = target
		if err := objs.Ports.Update(&key, &value, ebpf.UpdateAny); err != nil {
			Logger.Fatal("Failed to update ports map for target port", zap.Error(err), zap.Uint16("port", key.Port))
		}
	}

	Logger.Info("Rate limits set successfully",
		zap.Uint64("sim_rate_bps", simRule.RateLimitBps),
		zap.Ints("target ports ", config.C.Rule.Target.Ports),
		zap.Uint64("other_rate_bps", otherRule.RateLimitBps),
	)
}

// ----------------------------
// Print statistics
// ----------------------------
func printStats(m *ebpf.Map, key uint32, label string) {
	var values []gen.TcFlowCounter
	if err := m.Lookup(key, &values); err != nil {
		Logger.Error("Error reading stats", zap.String("label", label), zap.Error(err))
		return
	}

	var total gen.TcFlowCounter
	for _, v := range values {
		total.AcceptedBytes += v.AcceptedBytes
		total.DroppedBytes += v.DroppedBytes
		total.AcceptedPackets += v.AcceptedPackets
		total.DroppedPackets += v.DroppedPackets
	}

	Logger.Info("Traffic Stats",
		zap.String("label", label),
		zap.Uint64("accepted_bytes", total.AcceptedBytes),
		zap.Uint64("dropped_bytes", total.DroppedBytes),
		zap.Uint64("accepted_packets", total.AcceptedPackets),
		zap.Uint64("dropped_packets", total.DroppedPackets),
	)
}

func AttachProg() {
	if err := rlimit.RemoveMemlock(); err != nil {
		Logger.Fatal("Removing memlock rlimit failed", zap.Error(err))
	}

	var objs gen.TcObjects
	if err := gen.LoadTcObjects(&objs, nil); err != nil {
		Logger.Fatal("Failed to load eBPF objects", zap.Error(err))
	}
	defer objs.Close()
	Logger.Info("TC eBPF program loaded successfully")

	Logger.Info("Initializing rate limit configurations")
	updateMap(&objs)

	ifaceName := config.C.Rule.Iface
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		Logger.Fatal("Lookup network interface failed", zap.String("iface_name", ifaceName), zap.Error(err))
	}
	Logger.Debug("Network interface looked up", zap.String("iface", iface.Name), zap.Int("index", iface.Index))

	var progLink link.Link
	var attachErr error
	var direction string

	switch config.C.TargetGress {
	case 1: // EGRESS
		direction = "Egress"
		progLink, attachErr = link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   objs.Gress,
			Attach:    ebpf.AttachTCXEgress,
		})
	case 0: // INGRESS
		direction = "Ingress"
		progLink, attachErr = link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   objs.Gress,
			Attach:    ebpf.AttachTCXIngress,
		})
	default:
		Logger.Fatal("Invalid gress configuration", zap.String("gress", config.C.Rule.Gress))
	}

	if attachErr != nil {
		Logger.Fatal("Could not attach TCX program", zap.String("direction", direction), zap.String("iface", iface.Name), zap.Error(attachErr))
	}

	defer progLink.Close()

	Logger.Info("Successfully attached eBPF programs",
		zap.String("iface_name", iface.Name),
		zap.Int("iface_index", iface.Index))

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			Logger.Info("----- Traffic Statistics -----")
			printStats(objs.FlowStats, 0, "Simulation Traffic")
			printStats(objs.FlowStats, 1, "Other Traffic")
		}
	}()

	<-stop
	Logger.Info("Exiting and cleaning up")
}

// ----------------------------
// Main
// ----------------------------
func main() {
	LoadConfig()
	AttachProg()
}
