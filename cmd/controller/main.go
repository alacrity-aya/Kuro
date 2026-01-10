package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alacrity-aya/Kuro/internal/controller"
	"github.com/alacrity-aya/Kuro/internal/controller/config"
)

func main() {
	configPath := flag.String("config", "configs/kuro-emulation.yaml", "Path to emulation config")
	kubeconfig := flag.String("kubeconfig", "", "Path to kubeconfig file (optional)")
	agentLabel := flag.String("agent-label", "app=kuro-agent", "Label selector to find agents")
	namespace := flag.String("namespace", "default", "Namespace where agents run")
	verbose := flag.Bool("verbose", true, "Enable debug logging")
	flag.Parse()

	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})))

	slog.Info("Loading emulation configuration", "path", *configPath)
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		slog.Error("Failed to load config", "error", err)
		os.Exit(1)
	}

	mgr, err := controller.NewControllerManager(*kubeconfig)
	if err != nil {
		slog.Error("Failed to init controller manager", "error", err)
		os.Exit(1)
	}
	defer mgr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err = mgr.StartDiscovery(ctx, *namespace, *agentLabel); err != nil {
		slog.Error("Failed to start discovery", "error", err)
		os.Exit(1)
	}

	statusCh, err := mgr.MonitorAgents(ctx)
	if err != nil {
		slog.Error("Failed to start monitoring", "error", err)
		os.Exit(1)
	}

	go func() {
		for event := range statusCh {
			if event.Error != nil {
				slog.Debug("Agent monitor error", "agent", event.AgentAddr, "err", event.Error)
				continue
			}
			for _, wl := range event.Report.Workloads {
				slog.Info("Stats",
					"agent", event.AgentAddr,
					"pod", wl.PodName,
					"rate_bps", wl.TrafficStats.SmoothRateBps,
				)
			}
		}
	}()

	slog.Info("Waiting for agents to be discovered...")
	time.Sleep(3 * time.Second)

	slog.Info("Applying configuration to discovered agents")
	applyResults, err := mgr.ApplyConfig(ctx, cfg)
	if err != nil {
		slog.Error("Apply process failed", "error", err)
	}

	for addr, res := range applyResults {
		if res.Error != nil {
			slog.Error("Agent apply failed", "agent", addr, "error", res.Error)
		} else {
			slog.Info("Agent apply success", "agent", addr, "status", res.Response.Status)
		}
	}

	slog.Info("Controller running. Press Ctrl+C to stop.")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	slog.Info("Shutting down...")
}
