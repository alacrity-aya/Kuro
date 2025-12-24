// Package data is kuro's data panel. It can send flow statistics and some information like video flow, position etc to contorl panel
package data

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"kuro/loader"
	"kuro/netem"
	pb "kuro/proto"
	"kuro/spec"
	"kuro/topo"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
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
	info clientInfo

	client pb.AgentServiceClient

	// Ebpf loader
	bpfManager *loader.EbpfManager

	// Keep track of the current topology to tear it down on shutdown/reconfig
	topoManager *topo.RuntimeTopo

	// Network netem manager
	netemManager *netem.NetemManager
}

func NewDataClient(
	hostName string,
	agentVersion string,
	capabilities []string,
	ip string,

	conn *grpc.ClientConn,
) *DataClient {
	c := &DataClient{
		info:   clientInfo{hostName, agentVersion, capabilities, ip},
		client: pb.NewAgentServiceClient(conn),
	}

	return c
}

// TearDown cleans up network topology resources
func (c *DataClient) TearDown() {
	if c.topoManager != nil {
		slog.Info("Tearing down network topology...")
		if err := c.topoManager.TearDown(); err != nil {
			slog.Error("Failed to tear down topology", "error", err)
		}
		c.topoManager = nil
	}

	if c.bpfManager != nil {
		slog.Info("Clear bpf resource...")
		if err := c.bpfManager.Close(); err != nil {
			slog.Error("Failed to bpf resource", "error", err)
		}
		c.bpfManager = nil
	}
}

func (c *DataClient) startReporting(ctx context.Context) {
	const maxRetries = 3
	retries := 0

	slog.Info("Traffic reporting worker started")

	for retries < maxRetries {
		select {
		case <-ctx.Done():
			return
		default:
		}

		reportCtx := metadata.AppendToOutgoingContext(ctx, "x-host-name", c.info.hostName)
		stream, err := c.client.ReportTraffic(reportCtx)
		if err != nil {
			slog.Error("Failed to open stream", "error", err, "retry", retries)
			time.Sleep(2 * time.Second)
			retries++
			continue
		}

		err = c.uploadStats(ctx, stream)
		if err != nil {
			slog.Warn("Stream broken, will reconnect", "error", err, "retry", retries)
			retries++
			time.Sleep(2 * time.Second)
			continue
		}

		return
	}
	slog.Error("Traffic reporting stopped: max retries exceeded")
}

func (c *DataClient) uploadStats(ctx context.Context, stream pb.AgentService_ReportTrafficClient) error {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			stream.CloseAndRecv()
			return nil
		case <-ticker.C:
			ifaceStatsList := c.bpfManager.CollectStats()
			for _, ifaceStat := range ifaceStatsList {
				pbStat := &pb.TrafficStats{
					NodeName:             c.info.hostName,
					IfaceName:            ifaceStat.IfaceName,
					TotalAcceptedBytes:   ifaceStat.Stat.TotalAcceptedBytes,
					TotalDroppedBytes:    ifaceStat.Stat.TotalDroppedBytes,
					TotalAcceptedPackets: ifaceStat.Stat.TotalAcceptedPackets,
					TotalDroppedPackets:  ifaceStat.Stat.TotalDroppedPackets,
					InstantRateBps:       ifaceStat.Stat.InstantRateBps,
					SmoothRateBps:        ifaceStat.Stat.SmoothRateBps,
					Timestamp:            uint64(ifaceStat.Stat.TimeStamp.UnixMilli()),
				}

				if err := stream.Send(pbStat); err != nil {
					if err == io.EOF {
						_, recvErr := stream.CloseAndRecv()
						return recvErr
					}
					return err
				}
			}
		}
	}
}

func (c *DataClient) run(ctx context.Context) error {
	defer c.TearDown()

	// Use the ctrlStream context to monitor connection state
	ctrlStream, err := c.client.ControlStream(ctx)
	if err != nil {
		return err
	}

	// --- Stage 1: Handshake with Timeout ---
	// We expect the server to send ApplyConfig within a specific window
	configTimeout := 10 * time.Second
	timer := time.NewTimer(configTimeout)
	defer timer.Stop()

	// Send Hello first
	err = ctrlStream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Hello{
		Hello: &pb.Hello{HostName: c.info.hostName, Ip: c.info.ip, AgentVersion: c.info.agentVersion},
	}})
	if err != nil {
		return err
	}

	// Result channel for async Recv
	type recvRes struct {
		msg *pb.ServerMessage
		err error
	}
	resChan := make(chan recvRes, 1)

	go func() {
		m, e := ctrlStream.Recv()
		resChan <- recvRes{m, e}
	}()

	var messageConfig *pb.ApplyNodeConfig
	select {
	case res := <-resChan:
		if res.err != nil {
			return fmt.Errorf("failed to receive config: %w", res.err)
		}
		messageConfig = res.msg.GetApplyConfig()
		if messageConfig == nil {
			return fmt.Errorf("protocol error: expected config, got nil")
		}
	case <-timer.C:
		return fmt.Errorf("server timed out sending configuration")
	case <-ctx.Done():
		return ctx.Err()
	}

	// --- Stage 2: Apply Config & ACK & Report flow ---
	err = c.applyNodeConfig(messageConfig)
	if err != nil {
		ctrlStream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Ack{Ack: &pb.Ack{Ok: false, Message: err.Error()}}})
		return err
	}

	if err := ctrlStream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Ack{Ack: &pb.Ack{Ok: true}}}); err != nil {
		return err
	}

	reportCtx, cancleReport := context.WithCancel(ctx)
	defer cancleReport()
	go c.startReporting(reportCtx)

	// --- Stage 3: Heartbeat Loop with Receive Timeout ---
	// If we don't receive a heartbeat response from the server, we consider it offline.
	heartbeatInterval := 5 * time.Second
	serverTimeout := 15 * time.Second // Must be > interval
	timer.Reset(serverTimeout)

	slog.Info("Client entering running state with heartbeat monitoring")

	for {
		// Launch receiver for heartbeat responses or async errors
		go func() {
			m, e := ctrlStream.Recv()
			resChan <- recvRes{m, e}
		}()

		// Ticker for sending heartbeats
		ticker := time.NewTicker(heartbeatInterval)

		select {
		case <-ticker.C:
			// Send heartbeat to server
			err := ctrlStream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Heartbeat{
				Heartbeat: &pb.Heartbeat{Timestamp: time.Now().UnixMilli()},
			}})
			if err != nil {
				ticker.Stop()
				return err
			}

		case res := <-resChan:
			if res.err != nil {
				ticker.Stop()
				return fmt.Errorf("stream read error: %w", res.err)
			}

			// We received something from server, reset the "Server Alive" timer
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(serverTimeout)

			// Process server message (e.g., Heartbeat ACK)
			if hb := res.msg.GetHeartbeat(); hb != nil {
				slog.Debug("Server heartbeat ACK received", "server_time", hb.Timestamp)
			}

		case <-timer.C:
			ticker.Stop()
			slog.Error("Server is considered offline: heartbeat response timeout")
			return fmt.Errorf("server heartbeat timeout")

		case <-ctx.Done():
			ticker.Stop()
			return ctx.Err()
		}
		ticker.Stop() // Cleanup ticker before next loop iteration
	}
}

func (c *DataClient) applyNodeConfig(config *pb.ApplyNodeConfig) error {
	slog.Debug("Applying node config",
		"host", config.HostName,
		"nodes", config.Nodes,
	)

	specs, err := spec.BuildSpecs(config)
	if err != nil {
		return err
	}

	slog.Debug("Build specs", "specs", specs)
	c.TearDown()

	t := topo.NewRuntimeTopo(specs.TopoSpec)
	if err = t.Setup(); err != nil {
		return fmt.Errorf("setup network topology failed: %w", err)
	}
	c.topoManager = t

	// TODO: remove netemManager
	_ = netem.NewNetemManager(specs.NetemSpecs)
	// err = n.Apply()
	// if err != nil {
	// 	return fmt.Errorf("set netem rules failed: %v", err)
	// }
	// c.netemManager = n

	l := loader.NewEbpfManager()
	if err := l.Sync(specs.ProgramSpecs, specs.RouteSpecs, specs.NetemSpecs); err != nil {
		return fmt.Errorf("failed to load eBPF programs and attachments, err: %v", err)
	}
	slog.Info("eBPF programs loaded and attached successfully.")

	c.bpfManager = l

	// optional debug print
	c.inspectMetadata()

	return nil
}

func (c *DataClient) inspectMetadata() {
	fmt.Println("\n===========  inspectMetadata  ===========")

	c.bpfManager.InspectMetadata()
	c.netemManager.Inspect()
	c.topoManager.InspectTopology()

	fmt.Println("\n=========================================")
}

// TODO: RunDataClient should record args: agentVersion capabilities ip

func RunDataClient(target, hostName string, agentVersion string, capabilities []string, ip string) error {
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
			dataClient := NewDataClient(hostName, agentVersion, capabilities, ip, conn)

			if err := dataClient.run(ctx); err != nil {
				slog.Error("DataClient run error (reconnecting...)", "error", err)
			}

			// close older connect, ready to reconnect
			_ = conn.Close()
			time.Sleep(2 * time.Second)
		}
	}
}
