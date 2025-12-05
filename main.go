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

func loop() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			fmt.Printf("ebpf is running...\n")

		case <-ctx.Done():
			fmt.Println("\nreceive (SIGINT/SIGTERM)")
			fmt.Println("exit")
			return
		}
	}
}

func main() {
	// TODO: any rule shoule be atmoic, either successful or failed

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

	loop()
}
