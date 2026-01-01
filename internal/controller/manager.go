// Package controller
package controller

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	pb "github.com/alacrity-aya/Kuro/api/proto/v1"
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

// ApplyEmulationToAgent sends emulation command to agent
func (m *ControllerManager) ApplyEmulationToAgent(ctx context.Context, agentAddr string, req *pb.EmulationRequest) (*pb.EmulationResponse, error) {
	client, err := m.getOrConnectAgent(agentAddr)
	if err != nil {
		return nil, err
	}

	slog.Info("Sending EmulationRequest to agent", "agent", agentAddr, "request_id", req.RequestId)

	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	return client.ApplyEmulation(ctx, req)
}

func (m *ControllerManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.agents {
		a.conn.Close()
	}
}
