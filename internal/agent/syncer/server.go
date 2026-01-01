// Package syncer receive command from controller
package syncer

import (
	"context"
	"fmt"

	pb "github.com/alacrity-aya/Kuro/api/proto/v1"
	"github.com/alacrity-aya/Kuro/internal/spec"
)

type SyncerServer struct {
	pb.UnimplementedAgentServiceServer
	executor TaskExecutor
}

func NewSyncerServer(e TaskExecutor) *SyncerServer {
	return &SyncerServer{executor: e}
}

func (s *SyncerServer) ApplyEmulation(ctx context.Context, req *pb.EmulationRequest) (*pb.EmulationResponse, error) {
	// construct specs from req and executor

	var specs []spec.Spec
	var results []*pb.WorkloadApplyResult

	for _, wl := range req.Workloads {
		ifIndex, NsHandle, exists := s.executor.GetPodMetadata(wl.PodName)
		if !exists {
			results = append(results, &pb.WorkloadApplyResult{
				PodName:      wl.PodName,
				Success:      false,
				ErrorMessage: "Pod meta not found",
				ErrorCode:    pb.WorkloadApplyResult_ERROR_POD_NOT_FOUND,
			})
			continue
		}
		sItem := spec.Spec{
			IfaceIndex: ifIndex,
			NsHandle:   NsHandle,
		}

		if wl.RateLimit != nil {
			sItem.RateLimit = spec.RateLimitSpec{
				RateBytes:  wl.RateLimit.RateBps / 8,
				BurstBytes: wl.RateLimit.BurstBytes,
			}
		}

		if wl.Netem != nil {
			sItem.Netem = spec.NetemSpec{
				LatencyMs:   float64(wl.Netem.DelayMs),
				JitterMs:    float64(wl.Netem.JitterMs),
				LossPercent: float64(wl.Netem.LossPpm) / 10000.0,
			}
		}

		specs = append(specs, sItem)
		results = append(results, &pb.WorkloadApplyResult{PodName: wl.PodName, Success: true})
	}

	// TODO: results should be updated if err occurs
	// async here?
	if err := s.executor.ApplyRules(specs); err != nil {
		return &pb.EmulationResponse{Status: pb.EmulationResponse_APPLY_FAILED}, err
	}

	return &pb.EmulationResponse{
		RequestId: req.RequestId,
		Status:    pb.EmulationResponse_APPLY_SUCCESS,
		Results:   results,
	}, nil
}

func (s *SyncerServer) ReportStatus(context.Context, *pb.StatusReport) (*pb.StatusResponse, error) {
	return nil, fmt.Errorf("method ReportStatus not implemented on Agent Server-side")
}
