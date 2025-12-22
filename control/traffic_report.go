package control

import (
	"io"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "kuro/proto"
)

// ReportTraffic placeholder
func (s *AgentServer) ReportTraffic(stream pb.AgentService_ReportTrafficServer) error {
	ctx := stream.Context()

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing metadata")
	}

	hostNames := md.Get("x-host-name")
	if len(hostNames) == 0 {
		return status.Error(codes.Unauthenticated, "x-host-name not found in metadata")
	}

	hostName := hostNames[0]

	info, exist := s.registry.GetInfo(hostName)

	if !exist || !info.online {
		slog.Warn("traffic report rejected: host not online", "host", hostName)
		return status.Errorf(codes.FailedPrecondition, "host %s is not online, please hello first", hostName)
	}

	slog.Info("started receiving traffic report", "host", hostName)

	for {
		stats, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.ReportAck{
				Ok:      true,
				Message: "stats received and processing",
			})
		}
		if err != nil {
			slog.Error("traffic stream error", "host", hostName, "err", err)
			return err
		}

		slog.Warn("get from stream", "stats", stats)

		select {
		case s.statsChan <- &ReportedStat{HostName: hostName, Stats: stats}:
		default:
			slog.Warn("stats channel full, dropping data", "host", hostName)
		}
	}
}
