package main

import (
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	pb "github.com/alacrity-aya/Kuro/api/proto/v1"
	"github.com/alacrity-aya/Kuro/internal/agent"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

const (
	Port = ":50051"
)

func main() {
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, opts))

	slog.SetDefault(logger)
	logger.Info("Kuro Agent starts...")
	logger.Debug("Debug mod is enabled")

	lis, err := net.Listen("tcp", Port)
	if err != nil {
		logger.Error("unable to listen", "port", Port, "error", err)
		os.Exit(1)
	}

	kaep := keepalive.EnforcementPolicy{
		MinTime:             5 * time.Second,
		PermitWithoutStream: true,
	}
	kasp := keepalive.ServerParameters{
		MaxConnectionIdle: 15 * time.Second,
		Time:              10 * time.Second,
		Timeout:           2 * time.Second,
	}

	grpcServer := grpc.NewServer(
		grpc.KeepaliveEnforcementPolicy(kaep),
		grpc.KeepaliveParams(kasp),
	)

	agentServer := agent.NewServer(logger)
	pb.RegisterAgentServiceServer(grpcServer, agentServer)

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh
		logger.Info("stopping Agent...")
		grpcServer.GracefulStop()
	}()

	logger.Info("Agent gRPC Server is ready", "address", Port)
	if err := grpcServer.Serve(lis); err != nil {
		logger.Error("gRPC Server exit unexpectedly", "error", err)
		os.Exit(1)
	}
}
