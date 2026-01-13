package main

import (
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	pb "github.com/alacrity-aya/Kuro/api/proto/v1"
	"github.com/alacrity-aya/Kuro/internal/agent"

	"google.golang.org/grpc"
)

const (
	Port = ":50051"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)
	logger.Info("Kuro Agent starts...")

	lis, err := net.Listen("tcp", Port)
	if err != nil {
		logger.Error("unable to listen", "port", Port, "error", err)
		os.Exit(1)
	}

	grpcServer := grpc.NewServer()

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
