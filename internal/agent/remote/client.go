package remote

import (
	"context"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	pb "kuro/api/proto/v1"
	"kuro/internal/domain"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"
)

type Client struct {
	serverAddr string
	nodeName   string
	handler    AgentHandler

	conn *grpc.ClientConn

	// channels
	eventCh chan domain.PodEvent
	ackCh   chan domain.CommandAck
	stopCh  chan struct{}

	mu sync.Mutex
}

func NewClient(addr, nodeName string, handler AgentHandler) (*Client, error) {
	return &Client{
		serverAddr: addr,
		nodeName:   nodeName,
		handler:    handler,
		eventCh:    make(chan domain.PodEvent, 100),
		ackCh:      make(chan domain.CommandAck, 100),
		stopCh:     make(chan struct{}),
	}, nil
}

func (c *Client) Start(ctx context.Context) error {
	connectParams := grpc.ConnectParams{
		Backoff: backoff.Config{
			BaseDelay:  1.0 * time.Second,
			Multiplier: 1.6,
			Jitter:     0.2,
			MaxDelay:   10 * time.Second,
		},
		MinConnectTimeout: 20 * time.Second,
	}

	conn, err := grpc.NewClient(c.serverAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithConnectParams(connectParams),
	)
	if err != nil {
		return err
	}
	c.conn = conn

	go c.connectionManager(ctx)

	return nil
}

func (c *Client) Stop() {
	close(c.stopCh)
	if c.conn != nil {
		c.conn.Close()
	}
}

func (c *Client) EnqueueEvent(event domain.PodEvent) {
	select {
	case c.eventCh <- event:
	default:
		log.Printf("[Remote] Event buffer full, dropping event for pod %s", event.PodName)
	}
}

// connectionManager maintain Stream life cycle
func (c *Client) connectionManager(ctx context.Context) {
	log.Printf("[Remote] Connection Manager started, target: %s", c.serverAddr)

	client := pb.NewSimulationAgentServiceClient(c.conn)

	retryDelay := 1 * time.Second
	maxDelay := 30 * time.Second

	for {
		select {
		case <-c.stopCh:
			return
		case <-ctx.Done():
			return
		default:
		}

		streamCtx, cancel := context.WithCancel(ctx)
		stream, err := client.ControlStream(streamCtx)
		if err != nil {
			log.Printf("[Remote] Failed to create stream: %v. Retrying in %v...", err, retryDelay)
			time.Sleep(retryDelay)
			retryDelay *= 2
			if retryDelay > maxDelay {
				retryDelay = maxDelay
			}
			cancel()
			continue
		}

		retryDelay = 1 * time.Second
		log.Println("[Remote] Stream connected successfully")

		errCh := make(chan error, 2)

		go c.recvLoop(stream, errCh)
		go c.sendLoop(streamCtx, stream, errCh)

		select {
		case <-c.stopCh:
			cancel()
			return
		case <-ctx.Done():
			cancel()
			return
		case err := <-errCh:
			log.Printf("[Remote] Stream broken: %v. Reconnecting...", err)
			cancel() // cancle streamCtx, stop recvLoop and sendLoop
		}
	}
}

// recvLoop handles reading, parsing commands, and generating ACKs
func (c *Client) recvLoop(stream pb.SimulationAgentService_ControlStreamClient, errCh chan<- error) {
	for {
		cmd, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				errCh <- fmt.Errorf("server closed stream")
			} else {
				errCh <- err
			}
			return
		}
		c.handleCommand(cmd)
	}
}

// sendLoop centralizes all Stream.Send operations (Single-threaded write to avoid race conditions)
func (c *Client) sendLoop(ctx context.Context, stream pb.SimulationAgentService_ControlStreamClient, errCh chan<- error) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	if err := c.sendHeartbeat(stream); err != nil {
		errCh <- err
		return
	}

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			if err := c.sendHeartbeat(stream); err != nil {
				errCh <- err
				return
			}

		case event := <-c.eventCh:
			if err := c.sendPodEvent(stream, event); err != nil {
				errCh <- err
				return
			}

		case ack, ok := <-c.ackCh:

			if !ok {
				log.Println("[Remote] Critical: ackCh is closed, stopping sendLoop")
				return
			}
			pbAck := ToProtoAck(ack)

			pbMsg := &pb.AgentMsg{
				Timestamp: ack.Timestamp.UnixNano(),
				Payload:   &pb.AgentMsg_Ack{Ack: pbAck},
			}

			if err := stream.Send(pbMsg); err != nil {
				// handle error
			}
		}
	}
}

func (c *Client) sendHeartbeat(stream pb.SimulationAgentService_ControlStreamClient) error {
	hbDomain := c.handler.GetAgentStatus()
	pbHb := ToProtoHeartbeat(hbDomain)
	pbHb.NodeName = c.nodeName

	msg := &pb.AgentMsg{
		Timestamp: time.Now().UnixNano(),
		Payload:   &pb.AgentMsg_Heartbeat{Heartbeat: pbHb},
	}
	return stream.Send(msg)
}

func (c *Client) sendPodEvent(stream pb.SimulationAgentService_ControlStreamClient, event domain.PodEvent) error {
	pbEvent := ToProtoPodEvent(event)
	msg := &pb.AgentMsg{
		Timestamp: time.Now().UnixNano(),
		Payload:   &pb.AgentMsg_PodEvent{PodEvent: pbEvent},
	}
	return stream.Send(msg)
}

func (c *Client) handleCommand(cmd *pb.ControllerCmd) {
	var err error
	var msg string

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

	select {
	case c.ackCh <- domainAck:
	default:
		log.Printf("[Remote] ACK buffer full, dropping ACK for cmd %s", cmd.CommandId)
	}
}
