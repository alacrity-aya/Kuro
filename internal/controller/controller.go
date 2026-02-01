package controller

import (
	"fmt"
	"log"
	"net"
	"sync"

	pb "kuro/api/v1" // Used only for gRPC Server registration, not business logic
	"kuro/internal/controller/rpc"
	"kuro/internal/domain"

	"github.com/google/uuid"
	"google.golang.org/grpc"
)

// ControllerManager is the core logic unit
type ControllerManager struct {
	// activeAgents maps NodeName -> domain.AgentSender
	// Stores interfaces to ensure complete decoupling
	activeAgents sync.Map
	grpcPort     int
}

func NewControllerManager(grpcPort int) *ControllerManager {
	return &ControllerManager{
		grpcPort: grpcPort,
	}
}

// RunAgentServer starts the gRPC service.
// Note: The HTTP service is now started externally (cmd/main.go)
// by calling the api package; it is no longer started here.
func (c *ControllerManager) RunAgentServer() error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", c.grpcPort))
	if err != nil {
		return fmt.Errorf("failed to listen on grpc port %d: %w", c.grpcPort, err)
	}

	grpcServer := grpc.NewServer()

	// Inject self as the Manager implementation
	rpcService := rpc.NewServer(c)
	pb.RegisterSimulationAgentServiceServer(grpcServer, rpcService)

	log.Printf("[Controller] gRPC Server listening on :%d", c.grpcPort)
	return grpcServer.Serve(lis)
}

// =============================================================
// Implementation of rpc.AgentManager Interface
// =============================================================

func (c *ControllerManager) RegisterAgent(nodeName string, sender domain.AgentSender) {
	c.activeAgents.Store(nodeName, sender)
	log.Printf("[Controller] Agent Registered: %s", nodeName)
}

func (c *ControllerManager) UnregisterAgent(nodeName string) {
	c.activeAgents.Delete(nodeName)
	log.Printf("[Controller] Agent Disconnected: %s", nodeName)
}

func (c *ControllerManager) HandleHeartbeat(nodeName string, hb domain.Heartbeat) {
	// log.Printf("[Heartbeat] Node: %s, Pods: %d", nodeName, hb.ManagedPodCount)
}

func (c *ControllerManager) HandlePodEvent(nodeName string, event domain.PodEvent) {
	log.Printf("[Topology] Node %s report: Pod %s (%d) IP=%s",
		nodeName, event.PodName, event.Type, event.PodIP)
}

func (c *ControllerManager) HandleAck(nodeName string, ack domain.CommandAck) {
	status := "Success"
	if !ack.Success {
		status = fmt.Sprintf("Failed (%s)", ack.Message)
	}
	log.Printf("[Ack] Node: %s, ID: %s, Status: %s", nodeName, ack.CommandID, status)
}

// =============================================================
// Business Logic Methods (Exposed to HTTP API)
// =============================================================

// SendCommand is a generic dispatch method
func (c *ControllerManager) SendCommand(nodeName string, payload interface{}) (string, error) {
	val, ok := c.activeAgents.Load(nodeName)
	if !ok {
		return "", fmt.Errorf("agent on node '%s' not connected", nodeName)
	}
	sender := val.(domain.AgentSender)

	cmdID := uuid.New().String()
	cmd := domain.ControllerCommand{
		ID:      cmdID,
		Payload: payload,
	}

	if err := sender.Send(cmd); err != nil {
		return "", err
	}
	return cmdID, nil
}

// ListAgents returns the list of currently online Agents
func (c *ControllerManager) ListAgents() []string {
	agents := []string{}
	c.activeAgents.Range(func(key, value any) bool {
		agents = append(agents, key.(string))
		return true
	})
	return agents
}

// Wrapper methods for specific policies if needed, or caller uses SendCommand directly
