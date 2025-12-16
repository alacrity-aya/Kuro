// Package data is kuro's data panel. It can send flow statistics and some information like video flow, position etc to contorl panel
package data

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"time"

	"kuro/loader"
	pb "kuro/proto"
	"kuro/utils"

	"google.golang.org/grpc"
)

type DataState int

const (
	StateInit DataState = iota
	StateConfigApplied
	StateRunning
)

type DataClient struct {
	hostName string
	manager  *loader.EbpfManager
	client   pb.ControlPlaneServiceClient

	state atomic.Value  // DataState
	ready chan struct{} // congest sendLoop
}

func NewDataClient(
	hostName string,
	manager *loader.EbpfManager,
	conn *grpc.ClientConn,
) *DataClient {
	c := &DataClient{
		hostName: hostName,
		manager:  manager,
		client:   pb.NewControlPlaneServiceClient(conn),
	}

	c.state.Store(StateInit)
	return c
}

func (c *DataClient) Run(ctx context.Context) error {
	stream, err := c.client.ControlStream(ctx)
	if err != nil {
		return err
	}
	slog.Info("ControlStream established", "host", c.hostName)

	// control -> data
	recvErr := make(chan error, 1)
	go func() {
		recvErr <- c.recvLoop(ctx, stream)
	}()

	// data -> control
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- c.sendLoop(ctx, stream)
	}()

	// exit client
	select {
	case <-ctx.Done():
		_ = stream.CloseSend()
		return ctx.Err()
	case err := <-recvErr:
		return err
	case err := <-sendErr:
		return err
	}
}

func (c *DataClient) sendLoop(
	ctx context.Context,
	stream pb.ControlPlaneService_ControlStreamClient,
) error {
	select {
	case <-c.ready:
		slog.Info("configuration ready, start sending stats")
	case <-ctx.Done():
		return ctx.Err()
	}

	statsTicker := time.NewTicker(1 * time.Second)
	heartbeatTicker := time.NewTicker(5 * time.Second)

	defer statsTicker.Stop()
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-statsTicker.C:
			c.sendTrafficStats(stream)

		case <-heartbeatTicker.C:
			err := stream.Send(&pb.ControlMessage{
				Payload: &pb.ControlMessage_Heartbeat{
					Heartbeat: &pb.Heartbeat{
						Timestamp: time.Now().UnixMilli(),
					},
				},
			})
			if err != nil {
				return err
			}
		}
	}
}

func (c *DataClient) sendTrafficStats(
	stream pb.ControlPlaneService_ControlStreamClient,
) {
	stats := c.manager.CollectStats()

	// TODO: use goroutine here
	for _, s := range stats {
		nodeName, err := utils.NodeNameFromEth(s.IfaceName)
		if err != nil {
			slog.Warn("failed to get node name from eth", "ifaceName", s.IfaceName, "error", err)
			continue
		}

		msg := &pb.ControlMessage{
			Payload: &pb.ControlMessage_TrafficStats{
				TrafficStats: &pb.TrafficStats{
					NodeName:             nodeName,
					IfaceName:            s.IfaceName,
					TotalAcceptedBytes:   s.Stat.TotalAcceptedBytes,
					TotalDroppedBytes:    s.Stat.TotalDroppedBytes,
					TotalAcceptedPackets: s.Stat.TotalAcceptedPackets,
					TotalDroppedPackets:  s.Stat.TotalDroppedPackets,
					InstantRateBps:       s.Stat.InstantRateBps,
					SmoothRateBps:        s.Stat.SmoothRateBps,
					Timestamp:            s.Stat.TimeStamp.UnixMilli(),
				},
			},
		}

		if err := stream.Send(msg); err != nil {
			slog.Error("send traffic stats failed", "err", err)
			return
		}
	}
}

func (c *DataClient) recvLoop(
	ctx context.Context,
	stream pb.ControlPlaneService_ControlStreamClient,
) error {
	for {
		msg, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				slog.Info("stream closed by control")
				return nil
			}
			return err
		}

		switch payload := msg.Payload.(type) {

		case *pb.ControlMessage_NodeConfig:
			c.applyNodeConfig(payload.NodeConfig)

		case *pb.ControlMessage_Ack:
			slog.Info("received ack", "msg", payload.Ack.Message)

		default:
			slog.Warn("unknown control message")
		}
	}
}

func (c *DataClient) applyNodeConfig(cfg *pb.ApplyNodeConfig) {
	if cfg.HostName != c.hostName {
		return
	}

	slog.Info("Applying node config",
		"host", cfg.HostName,
		"nodes", cfg.Nodes,
	)

	// for _, node := range cfg.Nodes {
	// 	// TODO:
	// 	// - setup tc
	// 	// - setup netem
	// 	// - setup vxlan
	// }

	if c.state.Load().(DataState) == StateInit {
		c.state.Store(StateRunning)
		close(c.ready)
	}
}
