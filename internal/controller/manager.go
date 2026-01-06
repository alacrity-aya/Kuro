// Package controller
package controller

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	pb "github.com/alacrity-aya/Kuro/api/proto/v1"
	"github.com/alacrity-aya/Kuro/internal/controller/config"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type AgentClient struct {
	pb.AgentServiceClient
	conn *grpc.ClientConn
	addr string
}

// ControllerManager is responsible for managering all AgentClient
type ControllerManager struct {
	mu     sync.RWMutex
	agents map[string]*AgentClient // key: agent_addr (e.g. "192.168.1.10:50051")
}

func NewControllerManager() *ControllerManager {
	return &ControllerManager{
		agents: make(map[string]*AgentClient),
	}
}

// getOrConnectAgent gets current connection or establishs new connection
func (m *ControllerManager) getOrConnectAgent(addr string) (*AgentClient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if client, ok := m.agents[addr]; ok {
		return client, nil
	}

	slog.Debug("Creating new connection to agent", "addr", addr)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("did not connect to agent %s: %v", addr, err)
	}

	client := &AgentClient{
		AgentServiceClient: pb.NewAgentServiceClient(conn),
		conn:               conn,
		addr:               addr,
	}
	m.agents[addr] = client
	return client, nil
}

func (m *ControllerManager) ApplyConfig(ctx context.Context, cfg *config.EmulationConfig) (*pb.EmulationResponse, error) {
	req := m.buildRequest(cfg)

	return m.applyEmulationToAgent(ctx, cfg.TargetAgentAddr, req)
}

// applyEmulationToAgent sends emulation command to agent
func (m *ControllerManager) applyEmulationToAgent(ctx context.Context, agentAddr string, req *pb.EmulationRequest) (*pb.EmulationResponse, error) {
	client, err := m.getOrConnectAgent(agentAddr)
	if err != nil {
		return nil, err
	}

	slog.Info("Sending EmulationRequest to agent", "agent", agentAddr, "request_id", req.RequestId, "workloads_count", len(req.Workloads))

	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	return client.ApplyEmulation(ctx, req)
}

func (m *ControllerManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for addr, a := range m.agents {
		slog.Debug("Closing connection", "addr", addr)
		a.conn.Close()
	}
}

// buildRequest yaml -> protobuf
func (m *ControllerManager) buildRequest(cfg *config.EmulationConfig) *pb.EmulationRequest {
	req := &pb.EmulationRequest{
		RequestId:     uuid.New().String(),
		ConfigVersion: cfg.ConfigVersion,
		Workloads:     make([]*pb.WorkloadEmulation, 0, len(cfg.Workloads)),
	}

	for _, w := range cfg.Workloads {
		pbWorkload := &pb.WorkloadEmulation{
			PodName: w.PodName,
		}

		if w.RateLimit != nil {
			pbWorkload.RateLimit = &pb.RateLimit{
				RateBps:    w.RateLimit.RateBps,
				BurstBytes: w.RateLimit.BurstBytes,
			}
		}

		if w.Netem != nil {
			pbWorkload.Netem = &pb.Netem{
				DelayMs:  w.Netem.DelayMs,
				JitterMs: w.Netem.JitterMs,
				LossPpm:  w.Netem.LossPpm,
			}
		}

		req.Workloads = append(req.Workloads, pbWorkload)
	}

	return req
}

func (m *ControllerManager) MonitorAgent(ctx context.Context, agentAddr string) error {
	client, err := m.getOrConnectAgent(agentAddr)
	if err != nil {
		return err
	}

	stream, err := client.WatchStatus(ctx, &pb.WatchStatusRequest{})
	if err != nil {
		return fmt.Errorf("failed to start watch: %w", err)
	}

	go func() {
		for {
			report, err := stream.Recv()
			if err != nil {
				slog.Error("Stream disconnected", "agent", agentAddr, "error", err)
				return
			}

			for _, wl := range report.Workloads {
				slog.Info("Stats Received",
					"agent", agentAddr,
					"pod", wl.PodName,
					"rate", wl.TrafficStats.SmoothRateBps)
			}
		}
	}()

	return nil
}
