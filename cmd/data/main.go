package main

import (
	"fmt"
	"log"
	"log/slog"
	"os"

	"kuro/data"
	"kuro/loader"
	"kuro/netem"
	"kuro/topo"
)

// ConvertToSpecs  TODO: move this function to another package

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
