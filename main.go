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

	for {
		select {
		case <-time.After(1 * time.Second):
			fmt.Printf("ebpf is running...\n")

		case <-ctx.Done():
			fmt.Println("\nreceive (SIGINT/SIGTERM)")
			fmt.Println("exit")
			return
		}
	}
}

func main() {
	// TODO: RLIMIT_MEMLOCK
	slog.SetLogLoggerLevel(slog.LevelDebug)
	config.C.LoadConfig("config.toml")
	slog.Debug("LoadConfig complete", "config", config.C)

	resource := loader.LoadEbpf(&config.C)
	defer resource.Close()

	loop()
}
