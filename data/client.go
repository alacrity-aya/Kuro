// Package data is kuro's data panel. It can send flow statistics and some information like video flow, position etc to contorl panel
package data

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"kuro/loader"
	pb "kuro/proto"
	"kuro/spec"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type DataState int

const (
	StateInit DataState = iota
	StateConfigApplied
	StateRunning
)

type clientInfo struct {
	hostName     string
	agentVersion string
	capabilities []string
	ip           string
}
type DataClient struct {
	info    clientInfo
	manager *loader.EbpfManager
	client  pb.AgentServiceClient

	state atomic.Value  // DataState
	ready chan struct{} // congest sendLoop
}

func NewDataClient(
	hostName string,
	agentVersion string,
	capabilities []string,
	ip string,

	manager *loader.EbpfManager,
	conn *grpc.ClientConn,
) *DataClient {
	c := &DataClient{
		info:    clientInfo{hostName, agentVersion, capabilities, ip},
		manager: manager,
		client:  pb.NewAgentServiceClient(conn),
	}

	c.state.Store(StateInit)
	return c
}

func (c *DataClient) run(ctx context.Context) error {
	stream, err := c.client.ControlStream(ctx)
	if err != nil {
		return err
	}

	err = stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Hello{
		Hello: &pb.Hello{HostName: c.info.hostName, Ip: c.info.ip, AgentVersion: c.info.agentVersion, Capabilities: c.info.capabilities},
	}})
	if err != nil {
		return err
	}

	message, err := stream.Recv()
	if err != nil {
		return err
	}

	message_config := message.GetApplyConfig()
	if message_config == nil {
		return fmt.Errorf("expected to receive config from server")
	}

	err = c.applyNodeConfig(message_config)
	if err != nil {
		return err
	}

	err = stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Ack{
		Ack: &pb.Ack{Ok: true, Message: "kuro-Message", RefId: "kuro-RefId"},
	}})
	if err != nil {
		return err
	}

	return nil
}

func (c *DataClient) applyNodeConfig(config *pb.ApplyNodeConfig) error {
	slog.Info("Applying node config",
		"host", config.HostName,
		"nodes", config.Nodes,
	)

	specs, err := spec.BuildSpecs(config)
	if err != nil {
		return err
	}

	slog.Debug("Build specs", "specs", specs)

	// TODO:
	// - setup tc
	// - setup netem
	// - setup vxlan

	if c.state.Load().(DataState) == StateInit {
		c.state.Store(StateRunning)
		close(c.ready)
	}

	return nil
}

func RunDataClient(target, hostName string, agentVersion string, capabilities []string, ip string, manager *loader.EbpfManager) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// capture signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		slog.Info("Received interrupt, shutting down...")
		cancel()
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			// establish connection
			conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				slog.Error("Failed to create grpc client", "error", err)
				time.Sleep(5 * time.Second)
				continue
			}

			slog.Info("Connected to data plane", "target", target)
			dataClient := NewDataClient(hostName, agentVersion, capabilities, ip, manager, conn)

			if err := dataClient.run(ctx); err != nil {
				slog.Error("DataClient run error (reconnecting...)", "error", err)
			}

			// close older connect, ready to reconnect
			_ = conn.Close()
			time.Sleep(2 * time.Second)
		}
	}
}
