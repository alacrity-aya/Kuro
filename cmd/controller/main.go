package main

import (
	"context"
	"flag"
	"log/slog"
	"os"

	"github.com/alacrity-aya/Kuro/internal/controller"
	"github.com/alacrity-aya/Kuro/internal/controller/config"
)

func main() {
	configPath := flag.String("config", "configs/kuro-emulation.yaml", "Path to the emulation configuration file")
	verbose := flag.Bool("verbose", true, "Enable debug logging")
	flag.Parse()

	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{
		Level: logLevel,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, opts))
	slog.SetDefault(logger)

	slog.Info("Loading configuration", "path", *configPath)
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		slog.Error("Failed to load config", "error", err)
		os.Exit(1)
	}

	mgr := controller.NewControllerManager()
	defer mgr.Close()

	slog.Info("Applying configuration to agent", "agent_addr", cfg.TargetAgentAddr)

	resp, err := mgr.ApplyConfig(context.Background(), cfg)
	if err != nil {
		slog.Error("Failed to apply emulation config", "error", err)
		os.Exit(1)
	}

	slog.Info("Agent response received",
		"status", resp.Status.String(),
		"request_id", resp.RequestId,
		"message", resp.Message,
	)

	hasError := false
	for _, res := range resp.Results {
		if res.Success {
			slog.Info("Workload applied successfully", "pod", res.PodName)
		} else {
			slog.Error("Workload failed",
				"pod", res.PodName,
				"code", res.ErrorCode,
				"msg", res.ErrorMessage,
			)
			hasError = true
		}
	}

	if hasError {
		slog.Warn("Some workloads failed to apply")
		os.Exit(1)
	}

	slog.Info("All workloads applied successfully ✅")
}
