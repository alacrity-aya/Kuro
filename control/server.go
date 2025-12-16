// Package control is kuro's control panel.
// It can control network topology, receives data from data panels and persists / aggregates them.
package control

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"time"

	pb "kuro/proto"
)

type ControlServer struct {
	pb.UnimplementedControlPlaneServiceServer
	configMap map[string]*pb.ApplyNodeConfig

	mu sync.RWMutex
	// inject DB / aggregator / TSDB writer
}

func NewControlServer(configMap map[string]*pb.ApplyNodeConfig) *ControlServer {
	return &ControlServer{configMap: configMap}
}

func (s *ControlServer) ControlStream(
	stream pb.ControlPlaneService_ControlStreamServer,
) error {
	ctx := stream.Context()

	slog.Info("data panel connected")

	sendErr := make(chan error, 1)
	go func() {
		sendErr <- s.sendInitialConfigs("hostA", ctx, stream)
	}()

	for {
		select {
		case <-ctx.Done():
			slog.Info("control stream context done")
			return ctx.Err()

		case err := <-sendErr:
			if err != nil {
				slog.Error("send loop exited", "err", err)
				return err
			}

		default:
			msg, err := stream.Recv()
			if err == io.EOF {
				slog.Info("data panel closed stream")
				return nil
			}
			if err != nil {
				slog.Error("recv error", "err", err)
				return err
			}

			s.handleIncomingMessage(msg, stream)
		}
	}
}

func (s *ControlServer) sendInitialConfigs(
	hostName string,
	ctx context.Context,
	stream pb.ControlPlaneService_ControlStreamServer,
) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	slog.Info("sending node config", "host", hostName)
	cfg := s.configMap[hostName]

	err := stream.Send(&pb.ControlMessage{
		Payload: &pb.ControlMessage_NodeConfig{
			NodeConfig: cfg,
		},
	})
	if err != nil {
		return err
	}

	// keepalive / liveness
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := stream.Send(&pb.ControlMessage{
				Payload: &pb.ControlMessage_Heartbeat{
					Heartbeat: &pb.Heartbeat{
						Timestamp: time.Now().UnixMilli(),
					},
				},
			}); err != nil {
				return err
			}
		}
	}
}

func (s *ControlServer) handleIncomingMessage(
	msg *pb.ControlMessage,
	stream pb.ControlPlaneService_ControlStreamServer,
) {
	switch payload := msg.Payload.(type) {

	case *pb.ControlMessage_TrafficStats:
		s.handleTrafficStats(payload.TrafficStats)

	case *pb.ControlMessage_Ack:
		slog.Info("received ack",
			"ok", payload.Ack.Ok,
			"msg", payload.Ack.Message,
		)

	case *pb.ControlMessage_Heartbeat:
		slog.Debug("heartbeat from data panel",
			"ts", payload.Heartbeat.Timestamp,
		)

	default:
		slog.Warn("unknown control message")
	}
}

func (s *ControlServer) handleTrafficStats(stat *pb.TrafficStats) {
	slog.Debug(
		"traffic stats",
		"node", stat.NodeName,
		"iface", stat.IfaceName,
		"rx_bytes", stat.TotalAcceptedBytes,
		"drop_bytes", stat.TotalDroppedBytes,
		"rate", stat.InstantRateBps,
		"ts", stat.Timestamp,
	)
}
