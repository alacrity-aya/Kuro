package agent

import (
	"context"
	"log"
	"time"

	kurov1 "kuro/api/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// GrpcClient handles the connection to the Controller.
type GrpcClient struct {
	conn   *grpc.ClientConn
	client kurov1.SimulationAgentServiceClient
	stream kurov1.SimulationAgentService_ControlStreamClient

	nodeName string
	nodeIP   string
}

func NewGrpcClient(controllerAddr, nodeName, nodeIP string) (*GrpcClient, error) {
	// Connect to Controller (using insecure for dev, use TLS in prod)
	conn, err := grpc.NewClient(controllerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	c := kurov1.NewSimulationAgentServiceClient(conn)

	return &GrpcClient{
		conn:     conn,
		client:   c,
		nodeName: nodeName,
		nodeIP:   nodeIP,
	}, nil
}

// StartStream initiates the bidirectional stream.
func (c *GrpcClient) StartStream(ctx context.Context) error {
	stream, err := c.client.ControlStream(ctx)
	if err != nil {
		return err
	}
	c.stream = stream

	// Send initial Heartbeat to register
	if err := c.SendHeartbeat(0); err != nil {
		return err
	}

	// Start a goroutine to receive commands from Controller
	go c.receiveLoop()

	return nil
}

func (c *GrpcClient) SendHeartbeat(podCount int32) error {
	req := &kurov1.AgentMsg{
		Timestamp: time.Now().UnixNano(),
		Payload: &kurov1.AgentMsg_Heartbeat{
			Heartbeat: &kurov1.Heartbeat{
				NodeName:        c.nodeName,
				NodeIp:          c.nodeIP,
				ManagedPodCount: podCount,
			},
		},
	}
	return c.stream.Send(req)
}

func (c *GrpcClient) SendPodEvent(event *kurov1.PodLifecycleEvent) error {
	req := &kurov1.AgentMsg{
		Timestamp: time.Now().UnixNano(),
		Payload: &kurov1.AgentMsg_PodEvent{
			PodEvent: event,
		},
	}
	return c.stream.Send(req)
}

func (c *GrpcClient) receiveLoop() {
	for {
		cmd, err := c.stream.Recv()
		if err != nil {
			log.Printf("[Agent] Stream disconnected: %v", err)
			// TODO: Implement Reconnect logic
			return
		}

		// Handle Controller Commands
		switch payload := cmd.Payload.(type) {
		case *kurov1.ControllerCmd_SyncPeers:
			log.Printf("[Agent] Received Peer Sync: %d peers", len(payload.SyncPeers.PeerIps))
			// TODO: Call bpfManager.SyncWhitelist(payload.SyncPeers.PeerIps)

		case *kurov1.ControllerCmd_ApplyPolicy:
			log.Printf("[Agent] Received Policy for %s", payload.ApplyPolicy.PodName)
			// TODO: Call bpfManager.UpdateRule(...)
		}
	}
}

func (c *GrpcClient) Close() {
	c.conn.Close()
}
