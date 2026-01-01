// Package syncer receive command from controller
package syncer

import (
	"context"
	"fmt"
	"log/slog"

	pb "github.com/alacrity-aya/Kuro/api/proto/v1"
)

type SyncerServer struct {
	pb.UnimplementedAgentServiceServer
	executor TaskExecutor
}

func NewAgentServer(e TaskExecutor) *SyncerServer {
	return &SyncerServer{executor: e}
}

func (s *SyncerServer) ApplyEmulation(ctx context.Context, req *pb.EmulationRequest) (*pb.EmulationResponse, error) {
	slog.Info("Received Emulation Request", "req_id", req.RequestId, "version", req.ConfigVersion)
	return nil, nil
}

func (s *SyncerServer) ReportStatus(context.Context, *pb.StatusReport) (*pb.StatusResponse, error) {
	return nil, fmt.Errorf("method ReportStatus not implemented on Agent Server-side")
}
