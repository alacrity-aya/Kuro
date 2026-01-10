// Package syncer receive command from controller
package syncer

import (
	"context"

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
	var results []*pb.WorkloadApplyResult

	for _, wl := range req.Workloads {
		sItem := s.buildSpec(wl)

		err := s.executor.UpdateSpec(wl.PodName, sItem)

		res := &pb.WorkloadApplyResult{
			PodName: wl.PodName,
		}

		if err != nil {
			res.Success = false
			res.ErrorMessage = err.Error()
			res.ErrorCode = pb.WorkloadApplyResult_ERROR_EBPF_FAILED
		} else {
			res.Success = true
		}
		results = append(results, res)
	}

	return &pb.EmulationResponse{
		RequestId: req.RequestId,
		Status:    pb.EmulationResponse_APPLY_SUCCESS,
		Results:   results,
	}, nil
}

func (s *SyncerServer) buildSpec(wl *pb.WorkloadEmulation) spec.Spec {
	sItem := spec.Spec{
		PodName: wl.GetPodName(),
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
	return sItem
}

func (s *SyncerServer) WatchStatus(_ *pb.WatchStatusRequest, stream pb.AgentService_WatchStatusServer) error {
	return StreamHandler(s.executor, stream)
}
