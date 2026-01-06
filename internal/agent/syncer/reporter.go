package syncer

import (
	"context"
	"log/slog"
	"time"

	pb "github.com/alacrity-aya/Kuro/api/proto/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type StatusStream interface {
	Send(*pb.StatusReport) error
	Context() context.Context
}

func StreamHandler(executor TaskExecutor, stream StatusStream) error {
	slog.Info("Client connected to WatchStatus stream")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stream.Context().Done():
			slog.Info("WatchStatus stream closed by client")
			return nil
		case <-ticker.C:
			rawStats := executor.CollectAllStats()

			workloads := make([]*pb.ActiveWorkload, 0, len(rawStats))
			tsNow := timestamppb.Now()

			for _, s := range rawStats {
				pbStats := &pb.TrafficStats{
					Timestamp:            tsNow,
					TotalAcceptedBytes:   s.TotalAcceptedBytes,
					TotalDroppedBytes:    s.TotalDroppedBytes,
					TotalAcceptedPackets: s.TotalAcceptedPackets,
					TotalDroppedPackets:  s.TotalDroppedPackets,
					InstantRateBps:       s.InstantRateBps,
					SmoothRateBps:        s.SmoothRateBps,
				}
				wl := &pb.ActiveWorkload{
					PodName:      s.PodName,
					TrafficStats: pbStats,
				}
				workloads = append(workloads, wl)
			}

			if err := stream.Send(&pb.StatusReport{
				Timestamp: tsNow,
				Workloads: workloads,
			}); err != nil {
				slog.Error("Failed to stream status, closing", "error", err)
				return err
			}
		}
	}
}
