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
		podIP := wl.PodIp

		// parse pod iface
		ifIndex, ifName, err := traffic.ResolvePodInterface(podIP)
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

		// build spec
		spec := traffic.Spec{
			PodName:    wl.PodName,
			IfaceIndex: ifIndex,
			// IfaceName will be populated in program.apply
		}

		// build default rule TODO: if spec.DefaultRule can be empty
		if wl.DefaultRule != nil {
			spec.DefaultRule = convertPbRuleToInternal(wl.DefaultRule)
		}

		// 4. build link rule
		for _, r := range wl.Rules {
			spec.Rules = append(spec.Rules, convertPbRuleToInternal(r))
		}

		specs = append(specs, spec)

		results = append(results, &pb.WorkloadApplyResult{
			PodName: wl.PodName,
			Success: true,
		})
	}

	// apply all specs
	// TODO: using go routine optimize this
	if len(specs) > 0 {
		if err := s.Manager.Apply(specs...); err != nil {
			s.Logger.Error("apply eBPF rule failed", "err", err)

			// if an error occurs, return immediately
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

// Proto Rule -> Internal Rule
func convertPbRuleToInternal(r *pb.EmulationRule) traffic.Rule {
	rule := traffic.Rule{
		TargetIP: r.TargetIp,
	}

	if r.RateLimit != nil {
		rule.Rate = traffic.RateLimitSpec{
			RateBytes:  r.RateLimit.RateBps / 8, // bit -> byte
			BurstBytes: r.RateLimit.BurstBytes,
		}
	}

	if r.Netem != nil {
		rule.Netem = traffic.NetemSpec{
			LatencyMs:   r.Netem.DelayMs,
			JitterMs:    r.Netem.JitterMs,
			LossPercent: float64(r.Netem.LossPpm) / 10000.0, // ppm -> %
		}
	}

	return rule
}

// WatchStatus report status(traffic flow and applied rule)
func (s *Server) WatchStatus(req *pb.WatchStatusRequest, stream pb.AgentService_WatchStatusServer) error {
	// TODO: handle include_metrics here
	s.Logger.Info("WatchStatus", "include_metrics", req.IncludeMetrics)

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

					defaultRule := convertInternalRuleToPb(&spec.DefaultRule)

					var pbRules []*pb.EmulationRule
					for _, r := range spec.Rules {
						ruleCopy := r
						pbRules = append(pbRules, convertInternalRuleToPb(&ruleCopy))
					}

					appliedEmu = &pb.WorkloadEmulation{
						PodName:     spec.PodName,
						IfaceName:   stat.IfaceName,
						DefaultRule: defaultRule,
						Rules:       pbRules,
						// TODO: PodIp
					}
				}

				// build LinkTrafficStats
				var linkTrafficStats []*pb.LinkTrafficStats
				for _, linkStat := range stat.Stats {
					pbLinkStat := &pb.LinkTrafficStats{
						RemoteIp: linkStat.RemoteIP,
						Ingress: &pb.DirectionStats{
							TotalBytes:     linkStat.Ingress.TotalBytes,
							TotalPackets:   linkStat.Ingress.TotalPackets,
							DroppedBytes:   linkStat.Ingress.DroppedBytes,
							DroppedPackets: linkStat.Ingress.DroppedPackets,
							InstantRateBps: linkStat.Ingress.InstantRateBps,
							SmoothRateBps:  linkStat.Ingress.SmoothRateBps,
						},
						Egress: &pb.DirectionStats{
							TotalBytes:     linkStat.Egress.TotalBytes,
							TotalPackets:   linkStat.Egress.TotalPackets,
							DroppedBytes:   linkStat.Egress.DroppedBytes,
							DroppedPackets: linkStat.Egress.DroppedPackets,
							InstantRateBps: linkStat.Egress.InstantRateBps,
							SmoothRateBps:  linkStat.Egress.SmoothRateBps,
						},
					}
					linkTrafficStats = append(linkTrafficStats, pbLinkStat)
				}

				wl := &pb.ActiveWorkload{
					PodName:          stat.PodName,
					IfaceName:        stat.IfaceName,
					AppliedEmulation: appliedEmu,
					TrafficStats: &pb.TrafficStats{
						Timestamp: timestamppb.Now(),
						LinkStats: linkTrafficStats,
					},
				}
				report.Workloads = append(report.Workloads, wl)
			}

			slog.Debug("send reports to stream", "report", report.String())

			if err := stream.Send(report); err != nil {
				return err
			}
		}
	}
}

// Internal Rule -> Proto Rule
func convertInternalRuleToPb(r *traffic.Rule) *pb.EmulationRule {
	if r == nil {
		return nil
	}
	return &pb.EmulationRule{
		TargetIp: r.TargetIP,
		RateLimit: &pb.RateLimit{
			RateBps:    r.Rate.RateBytes * 8, // Byte -> Bit
			BurstBytes: r.Rate.BurstBytes,
		},
		Netem: &pb.Netem{
			DelayMs:  r.Netem.LatencyMs,
			JitterMs: r.Netem.JitterMs,
			LossPpm:  uint32(r.Netem.LossPercent * 10000), // % -> ppm
		},
	}
}
