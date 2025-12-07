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
	"kuro/loader"
)

func main() {
	slog.SetLogLoggerLevel(slog.LevelDebug)
	config.C.LoadConfig("config.toml")
	slog.Debug("LoadConfig complete", "config", config.C)

	manager := loader.NewEbpfManager()

	defer manager.Close()

	if err := manager.Load(&config.C); err != nil {
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
			stat, err := manager.GetIfaceStats("veth-a")
			if err != nil {
				slog.Warn("GetIfaceStats wanring", "error", err)
			}
			fmt.Println(stat)

		case <-ctx.Done():
			fmt.Println("\nreceive (SIGINT/SIGTERM)")
			fmt.Println("exit")
			return
		}
	}
}
