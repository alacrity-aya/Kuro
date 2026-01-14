// Package agent
package agent

import (
	"context"
	"log/slog"
	"time"

	pb "github.com/alacrity-aya/Kuro/api/proto/v1"
	"github.com/alacrity-aya/Kuro/internal/agent/traffic"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Server struct {
	pb.UnimplementedAgentServiceServer
	Logger  *slog.Logger
	Manager *traffic.BpfManager
}

func NewServer(logger *slog.Logger) *Server {
	return &Server{
		Logger:  logger,
		Manager: traffic.NewBpfManager(),
	}
}

// ApplyEmulation receive qos rules
func (s *Server) ApplyEmulation(ctx context.Context, req *pb.EmulationRequest) (*pb.EmulationResponse, error) {
	s.Logger.Info("ApplyEmulation", "req_id", req.RequestId, "workload_count", len(req.Workloads))

	var specs []traffic.Spec
	var results []*pb.WorkloadApplyResult

	for _, wl := range req.Workloads {
		s.Logger.Info(">>> WorkLoads",
			"pod_name", wl.PodName,
			"pod_ip", wl.PodIp,
			"rate_bps", wl.RateLimit.RateBps,
			"loss_ppm", wl.Netem.LossPpm,
			"delay_ms", wl.Netem.DelayMs,
		)

		podIP := wl.PodIp

		ifIndex, ifName, err := traffic.ResolvePodInterface(podIP)
		// parsing failed, return err
		if err != nil {
			s.Logger.Error("failed to parse Pod iface", "pod", wl.PodName, "ip", podIP, "err", err)
			results = append(results, &pb.WorkloadApplyResult{
				PodName:      wl.PodName,
				Success:      false,
				ErrorMessage: err.Error(),
			})
			continue
		}

		s.Logger.Info("parse Pod successfully", "pod", wl.PodName, "host_iface", ifName, "index", ifIndex)

		spec := traffic.Spec{
			PodName:    wl.PodName,
			IfaceIndex: ifIndex,
			RateLimit: traffic.RateLimitSpec{
				RateBytes:  wl.RateLimit.RateBps / 8, // bit -> byte
				BurstBytes: wl.RateLimit.BurstBytes,
			},
			Netem: traffic.NetemSpec{
				LatencyMs:   wl.Netem.DelayMs,
				JitterMs:    wl.Netem.JitterMs,
				LossPercent: float64(wl.Netem.LossPpm) / 10000.0, // ppm -> %
			},
		}
		specs = append(specs, spec)

		results = append(results, &pb.WorkloadApplyResult{
			PodName: wl.PodName,
			Success: true,
		})
	}

	if len(specs) > 0 {
		if err := s.Manager.Apply(specs...); err != nil {
			s.Logger.Error("apply eBPF rule failed", "err", err)
			return &pb.EmulationResponse{
				Status:  pb.EmulationResponse_APPLY_FAILED,
				Message: err.Error(),
			}, nil
		}
	}

	return &pb.EmulationResponse{
		RequestId: req.RequestId,
		Status:    pb.EmulationResponse_APPLY_SUCCESS,
		Results:   results,
	}, nil
}

// WatchStatus report status(traffic flow and applied rule)
func (s *Server) WatchStatus(req *pb.WatchStatusRequest, stream pb.AgentService_WatchStatusServer) error {
	s.Logger.Info("WatchStatus", "include_metrics", req.IncludeMetrics)
	// TODO: handle include_metrics here

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stream.Context().Done():
			s.Logger.Info("WatchStatus: agent disconnect from controller")
			return nil

		case <-ticker.C:
			rawStats := s.Manager.CollectStats()

			report := &pb.StatusReport{
				Timestamp: timestamppb.Now(),
				Workloads: make([]*pb.ActiveWorkload, 0, len(rawStats)),
			}

			for _, stat := range rawStats {
				var appliedEmu *pb.WorkloadEmulation
				if stat.CurrentSpec != nil {
					spec := stat.CurrentSpec
					appliedEmu = &pb.WorkloadEmulation{
						PodName:   spec.PodName,
						IfaceName: stat.IfaceName,
						RateLimit: &pb.RateLimit{
							RateBps:    spec.RateLimit.RateBytes * 8, // Byte -> Bit
							BurstBytes: spec.RateLimit.BurstBytes,
						},
						Netem: &pb.Netem{
							DelayMs:  spec.Netem.LatencyMs,
							JitterMs: spec.Netem.JitterMs,
							// % (0-100) -> ppm (0-1000000)
							LossPpm: uint32(spec.Netem.LossPercent * 10000),
						},
					}
				}

				wl := &pb.ActiveWorkload{
					PodName:          stat.PodName,
					IfaceName:        stat.IfaceName,
					AppliedEmulation: appliedEmu,
					TrafficStats: &pb.TrafficStats{
						Timestamp: timestamppb.Now(),
						// Ingress
						Ingress: &pb.DirectionStats{
							TotalBytes:     stat.Ingress.TotalBytes,
							TotalPackets:   stat.Ingress.TotalPackets,
							DroppedBytes:   stat.Ingress.DroppedBytes,
							DroppedPackets: stat.Ingress.DroppedPackets,
							InstantRateBps: stat.Ingress.InstantRateBps,
							SmoothRateBps:  stat.Ingress.SmoothRateBps,
						},
						// Egress
						Egress: &pb.DirectionStats{
							TotalBytes:     stat.Egress.TotalBytes,
							TotalPackets:   stat.Egress.TotalPackets,
							DroppedBytes:   stat.Egress.DroppedBytes,
							DroppedPackets: stat.Egress.DroppedPackets,
							InstantRateBps: stat.Egress.InstantRateBps,
							SmoothRateBps:  stat.Egress.SmoothRateBps,
						},
					},
				}
				report.Workloads = append(report.Workloads, wl)
			}

			if err := stream.Send(report); err != nil {
				return err
			}
		}
	}
}
