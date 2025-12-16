package main

import (
	"fmt"
	"log"
	"log/slog"
	"os"

	"kuro/config"
	"kuro/data"
	"kuro/loader"
	"kuro/netem"
	"kuro/spec"
	"kuro/topo"
	"kuro/utils"
)

// ConvertToSpecs  TODO: move this function to another package
func ConvertToSpecs(cfg config.HostConfig) ([]spec.ProgramSpec, []spec.RouteSpec, []spec.NetemSpec) {
	var progSpecs []spec.ProgramSpec
	var netemSpecs []spec.NetemSpec

	for _, node := range cfg.Nodes {
		progSpec := spec.ProgramSpec{
			IfaceName: utils.EthName(node.Name), // Assuming Node Name matches Host Interface Name
		}

		if node.TrafficShaping != nil {
			progSpec.RateLimit = &spec.RateLimitSpec{
				RateBytes:  node.TrafficShaping.RateBps,
				BurstBytes: node.TrafficShaping.BurstBytes,
			}
		}

		progSpecs = append(progSpecs, progSpec)

		if node.Netem != nil {
			limit := node.Netem.Limit
			if limit == 0 {
				limit = 1000
			}

			netemSpec := spec.NetemSpec{
				NsName:      utils.NetnsName(node.Name),
				IfaceName:   utils.PeerEthName(node.Name),
				LatencyMs:   node.Netem.DelayMs,
				JitterMs:    node.Netem.JitterMs,
				LossPercent: node.Netem.LossPct,
				Limit:       limit,
			}

			netemSpecs = append(netemSpecs, netemSpec)
		}

	}

	var routeSpecs []spec.RouteSpec
	for _, r := range cfg.Routes {
		routeSpecs = append(routeSpecs, spec.RouteSpec{
			DestIP:     r.DestIP,
			TargetNode: r.OutNode,
		})
	}

	return progSpecs, routeSpecs, netemSpecs
}

func main() {
	slog.SetLogLoggerLevel(slog.LevelInfo)

	manager := loader.NewEbpfManager()
	defer manager.Close()

	if err := data.RunDataClient("127.0.0.1:50051", "hostA", manager); err != nil {
		log.Fatalf("Data client stopped with error: %v", err)
	}

	hostName := "hostA"
	slog.Debug("main start...", "host name", hostName)

	topo := topo.NewRuntimeTopo(*cfg)

	err := topo.Setup()
	defer topo.TearDown()

	if err != nil {
		panic(fmt.Sprintf("Setup network topology failed: %v", err))
	}

	topo.PrintTopology()

	err = netem.SetNetems(netemSpecs...)
	if err != nil {
		panic(fmt.Sprintf("Set netem rules failed: %v", err))
	}

	if err := manager.Sync(programSpecs, routeSpecs); err != nil {
		slog.Error("Failed to load eBPF programs and attachments", "error", err)
		os.Exit(1)
	}
	slog.Info("eBPF programs loaded and attached successfully.")
}
