package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"kuro/config"
	"kuro/manager"
	"kuro/netem"
	"kuro/topo"
	"kuro/utils"
)

// ConvertToSpecs  TODO: move this function to another package
func ConvertToSpecs(cfg config.HostConfig) ([]manager.ProgramSpec, []manager.RouteSpec, []netem.NetemSpec) {
	var progSpecs []manager.ProgramSpec
	var netemSpecs []netem.NetemSpec

	for _, node := range cfg.Nodes {
		progSpec := manager.ProgramSpec{
			IfaceName: utils.EthName(node.Name), // Assuming Node Name matches Host Interface Name
		}

		if node.TrafficShaping != nil {
			progSpec.RateLimit = &manager.RateLimitSpec{
				RateBytes:  node.TrafficShaping.RateBps,
				BurstBytes: node.TrafficShaping.BurstBytes,
			}
		}

		progSpecs = append(progSpecs, progSpec)

		if node.Netem != nil {
			netemSpec := netem.NetemSpec{
				NsName:      utils.NetnsName(node.Name),
				IfaceName:   utils.PeerEthName(node.Name),
				LatencyMs:   node.Netem.DelayMs,
				JitterMs:    node.Netem.JitterMs,
				LossPercent: node.Netem.LossPct,
			}

			netemSpecs = append(netemSpecs, netemSpec)
		}

	}

	var routeSpecs []manager.RouteSpec
	for _, r := range cfg.Routes {
		routeSpecs = append(routeSpecs, manager.RouteSpec{
			DestIP:     r.DestIP,
			TargetNode: r.OutNode,
		})
	}

	return progSpecs, routeSpecs, netemSpecs
}

func main() {
	slog.SetLogLoggerLevel(slog.LevelDebug)

	hostName := "hostA"
	slog.Debug("main start...", "host name", hostName)

	cfg, err := config.LoadHostConfig("config.toml", hostName)
	if err != nil {
		panic(err)
	}
	slog.Debug("LoadConfig complete", "config", cfg)

	programSpecs, routeSpecs, netemSpecs := ConvertToSpecs(*cfg)
	slog.Debug("ConvertToSpecs", "programSpecs", programSpecs, "routeSpecs", routeSpecs, "netemSpecs", netemSpecs)

	topo := topo.NewRuntimeTopo(*cfg)

	err = topo.Setup()
	defer topo.TearDown()

	if err != nil {
		slog.Error("Setup network topology failed", "error", err)
	}

	topo.PrintTopology()

	mgr := manager.NewEbpfManager()
	defer mgr.Close()

	if err := mgr.Sync(programSpecs, routeSpecs); err != nil {
		slog.Error("Failed to load eBPF programs and attachments", "error", err)
		os.Exit(1)
	}
	slog.Info("eBPF programs loaded and attached successfully.")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// stat, err := manager.GetIfaceStats("veth-a")
			// if err != nil {
			// 	slog.Warn("GetIfaceStats wanring", "error", err)
			// }
			// fmt.Println(stat)

		case <-ctx.Done():
			fmt.Println("\nreceive (SIGINT/SIGTERM)")
			fmt.Println("exit")
			return
		}
	}
}
