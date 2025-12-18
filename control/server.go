// Package control is kuro's control panel.
// It can control network topology, receives data from data panels and persists / aggregates them.
package control

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	pb "kuro/proto"
)

type AgentServer struct {
	pb.UnimplementedAgentServiceServer
	registry NodeRegistry
	// inject DB / aggregator / TSDB writer
}

func NewAgentServer(config map[string]*pb.ApplyNodeConfig) *AgentServer {
	return &AgentServer{registry: NewMemRegistry(config)}
}

// TODO: Implement dynamic push via channel

func (s *AgentServer) ControlStream(stream pb.AgentService_ControlStreamServer) error {
	ctx := stream.Context()

	req, err := stream.Recv()
	if err != nil {
		return err
	}

	hello := req.GetHello()
	if hello == nil {
		return fmt.Errorf("first message must be hello")
	}

	config, err := s.registry.RegisterNode(ctx, hello)
	if err != nil {
		return err
	}

	err = stream.Send(&pb.ServerMessage{Payload: &pb.ServerMessage_ApplyConfig{ApplyConfig: config}})
	if err != nil {
		return err
	}

	ackMsg, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("failed to receive ack: %v", err)
	}

	// check if data apply config
	ack := ackMsg.GetAck()
	if ack == nil || !ack.Ok {
		reason := "unknown"
		if ack != nil {
			reason = ack.Message
		}
		return fmt.Errorf("client failed to apply config: %s", reason)
	}

	err = s.registry.UpdateNodeInfo(ctx, hello, true)
	if err != nil {
		return err
	}

	defer func() {
		_ = s.registry.UpdateNodeInfo(context.Background(), hello, false)
	}()

	for {
		in, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		switch in.Payload.(type) {
		case *pb.ClientMessage_Heartbeat:
			err := stream.Send(&pb.ServerMessage{
				Payload: &pb.ServerMessage_Heartbeat{
					Heartbeat: &pb.Heartbeat{Timestamp: time.Now().UnixMilli()},
				},
			})
			if err != nil {
				return err
			}
		case *pb.ClientMessage_Ack:
			slog.Info("receive ClientMessage_Ack")
		}
	}
}

func (s *AgentServer) ReportTraffic(stream pb.AgentService_ReportTrafficServer) error {
	return nil
}
