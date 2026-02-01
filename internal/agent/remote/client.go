package remote

import (
	"context"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	pb "kuro/api/v1"
	"kuro/internal/domain"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"
)

type Client struct {
	serverAddr string
	nodeName   string
	handler    AgentHandler // Dependency on interface, not concrete struct

	conn   *grpc.ClientConn
	stream pb.SimulationAgentService_ControlStreamClient

	// Used to receive events from the Watcher and send them to the gRPC stream
	eventCh chan domain.PodEvent
	stopCh  chan struct{}
	mu      sync.Mutex
}

func NewClient(addr, nodeName string, handler AgentHandler) (*Client, error) {
	return &Client{
		serverAddr: addr,
		nodeName:   nodeName,
		handler:    handler,
		eventCh:    make(chan domain.PodEvent, 100), // Buffered to prevent blocking the Watcher
		stopCh:     make(chan struct{}),
	}, nil
}

// Start initiates the gRPC connection and bidirectional stream processing
func (c *Client) Start(ctx context.Context) error {
	// Configure reconnection strategy
	connectParams := grpc.ConnectParams{
		Backoff: backoff.Config{
			BaseDelay:  1.0 * time.Second,
			Multiplier: 1.6,
			Jitter:     0.2,
			MaxDelay:   10 * time.Second,
		},
		MinConnectTimeout: 20 * time.Second,
	}

	// 1. Create the client (Non-blocking by default)
	conn, err := grpc.NewClient(c.serverAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithConnectParams(connectParams),
	)
	if err != nil {
		return err
	}
	c.conn = conn

	client := pb.NewSimulationAgentServiceClient(conn)

	// 2. Open the Stream immediately.
	log.Printf("[Remote] Connecting to Controller at %s...", c.serverAddr)
	stream, err := client.ControlStream(ctx)
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}
	c.stream = stream

	log.Println("[Remote] Stream opened, starting loops...")

	// Start receiving loop
	go c.recvLoop(stream)
	// Start sending loop (Heartbeats + Events)
	go c.sendLoop(ctx, stream)

	return nil
}

func (c *Client) Stop() {
	close(c.stopCh)
	if c.conn != nil {
		c.conn.Close()
	}
}

// EnqueueEvent now accepts a Domain Object
func (c *Client) EnqueueEvent(event domain.PodEvent) {
	select {
	case c.eventCh <- event:
	default:
		log.Printf("[Remote] Event buffer full, dropping event for pod %s", event.PodName)
	}
}

// recvLoop handles commands issued by the Controller
func (c *Client) recvLoop(stream pb.SimulationAgentService_ControlStreamClient) {
	for {
		cmd, err := stream.Recv()
		if err == io.EOF {
			log.Println("[Remote] Stream closed by server")
			return
		}
		if err != nil {
			log.Printf("[Remote] Stream receive error: %v", err)
			return
		}

		c.handleCommand(cmd)
	}
}

// sendLoop is responsible for sending heartbeats and events
func (c *Client) sendLoop(ctx context.Context, stream pb.SimulationAgentService_ControlStreamClient) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Send an immediate heartbeat for registration
	c.sendHeartbeat(stream)

	for {
		select {
		case <-c.stopCh:
			stream.CloseSend()
			return
		case <-ctx.Done():
			stream.CloseSend()
			return
		case <-ticker.C:
			c.sendHeartbeat(stream)
		case event := <-c.eventCh:
			c.sendPodEvent(stream, event)
		}
	}
}

func (c *Client) sendHeartbeat(stream pb.SimulationAgentService_ControlStreamClient) {
	// 1. Get Domain object
	hbDomain := c.handler.GetAgentStatus()

	// 2. Use Mapper to convert to Proto
	pbHb := ToProtoHeartbeat(hbDomain)

	// Supplement Proto-specific transport layer fields (if any)
	// Here we assume NodeName in Domain is sufficient, or force override to ensure consistency
	pbHb.NodeName = c.nodeName

	msg := &pb.AgentMsg{
		Timestamp: time.Now().UnixNano(),
		Payload:   &pb.AgentMsg_Heartbeat{Heartbeat: pbHb},
	}

	if err := stream.Send(msg); err != nil {
		log.Printf("[Remote] Failed to send heartbeat: %v", err)
	}
}

func (c *Client) sendPodEvent(stream pb.SimulationAgentService_ControlStreamClient, event domain.PodEvent) {
	// Convert using Mapper
	pbEvent := ToProtoPodEvent(event)

	msg := &pb.AgentMsg{
		Timestamp: time.Now().UnixNano(),
		Payload:   &pb.AgentMsg_PodEvent{PodEvent: pbEvent},
	}

	if err := stream.Send(msg); err != nil {
		log.Printf("[Remote] Failed to send pod event: %v", err)
	}
}

// handleCommand dispatches instructions to the Agent logic
func (c *Client) handleCommand(cmd *pb.ControllerCmd) {
	var err error
	var msg string

	// Core logic for converting Proto to Domain and executing calls
	switch payload := cmd.Payload.(type) {

	case *pb.ControllerCmd_ApplyLinkPolicy:
		domainPolicy := FromProtoLinkPolicy(payload.ApplyLinkPolicy)
		log.Printf("[Remote] Cmd: ApplyLinkPolicy (%s -> %s)", domainPolicy.SrcIP, domainPolicy.DstIP)
		err = c.handler.ApplyLinkPolicy(domainPolicy)

	case *pb.ControllerCmd_ApplyPolicy:
		domainPolicy := FromProtoPodPolicy(payload.ApplyPolicy)
		log.Printf("[Remote] Cmd: ApplyPolicy (Pod: %s)", domainPolicy.PodName)
		err = c.handler.ApplyPolicy(domainPolicy)

	case *pb.ControllerCmd_ApplyNodePolicy:
		domainPolicy := FromProtoNodePolicy(payload.ApplyNodePolicy)
		log.Printf("[Remote] Cmd: ApplyNodePolicy")
		err = c.handler.ApplyNodePolicy(domainPolicy)

	default:
		log.Printf("[Remote] Unknown command type received")
		return
	}

	// Send ACK
	success := true
	if err != nil {
		success = false
		msg = err.Error()
		log.Printf("[Remote] Command execution failed: %v", err)
	}

	domainAck := domain.CommandAck{
		CommandID: cmd.CommandId,
		Success:   success,
		Message:   msg,
	}

	ackMsg := &pb.AgentMsg{
		Timestamp: time.Now().UnixNano(),
		Payload: &pb.AgentMsg_Ack{
			Ack: ToProtoAck(domainAck),
		},
	}
	c.stream.Send(ackMsg)
}
