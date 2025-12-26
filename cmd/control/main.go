package main

import (
	"context"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"kuro/config"
	"kuro/control"
	pb "kuro/proto"

	"google.golang.org/grpc"
)

func main() {
	slog.SetLogLoggerLevel(slog.LevelDebug)

	simCfg, err := config.LoadConfig("config.toml")
	if err != nil {
		slog.Error("LoadConfig failed", "error", err)
		return
	}
	config := config.BuildApplyNodeConfigs(simCfg)

	grpcServer := grpc.NewServer()
	controlServer := control.NewAgentServer(config)

	ctx, cancle := context.WithCancel(context.Background())
	defer cancle()

	// port of victoriametrics
	controlServer.StartMetricsServer(ctx, ":5179")
	pb.RegisterAgentServiceServer(grpcServer, controlServer)

	// rpc port
	addr := ":50051"

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", addr, err)
	}

	slog.Info("control panel listening", "addr", addr)

	go func() {
		slog.Info("control panel listening", "addr", addr)
		if err := grpcServer.Serve(lis); err != nil {
			slog.Error("grpc server failed", "err", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	slog.Info("shutting down control panel...")
	grpcServer.GracefulStop()

	cancle()
	controlServer.Stop()

	slog.Info("Server exited gracefully")
}
