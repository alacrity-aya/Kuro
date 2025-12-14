// Package control is kuro's control panel.
// It can control network topology, receives data from data panels and persists / aggregates them.
package control

import (
	"io"
	"log/slog"

	pb "kuro/proto"
)

type ControlServer struct {
	pb.UnimplementedDataPlaneServiceServer

	// inject DB / aggregator / TSDB writer
}

func NewControlServer() *ControlServer {
	return &ControlServer{}
}

func (s *ControlServer) StreamTrafficStats(
	stream pb.DataPlaneService_StreamTrafficStatsServer,
) error {
	var received uint64

	for {
		stat, err := stream.Recv()
		if err == io.EOF {
			// client finished sending
			slog.Info("stream closed by client", "received", received)

			return stream.SendAndClose(&pb.StreamAck{
				Ok: true,
			})
		}
		if err != nil {
			slog.Error("stream recv error", "err", err)
			return err
		}

		received++

		s.handleTrafficStat(stat)
	}
}

func (s *ControlServer) handleTrafficStat(stat *pb.TrafficStats) {
	slog.Debug(
		"traffic stat",
		"node", stat.NodeName,
		"iface", stat.IfaceName,
		"rx_bytes", stat.TotalAcceptedBytes,
		"drop_bytes", stat.TotalDroppedBytes,
		"rate", stat.InstantRateBps,
		"ts", stat.Timestamp,
	)
}
