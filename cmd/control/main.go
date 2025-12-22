package main

import (
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
	slog.SetLogLoggerLevel(slog.LevelWarn)

	simCfg, nil := config.LoadConfig("config.toml")
	config := config.BuildApplyNodeConfigs(simCfg)

	grpcServer := grpc.NewServer()

	controlServer := control.NewAgentServer(config)
	pb.RegisterAgentServiceServer(grpcServer, controlServer)

	addr := ":50051"

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", addr, err)
	}

	slog.Info("control panel listening", "addr", addr)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		slog.Info("shutting down control panel...")
		grpcServer.GracefulStop()
	}()

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("grpc server failed: %v", err)
	}
}
