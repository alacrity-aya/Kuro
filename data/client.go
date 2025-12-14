// Package data is kuro's data panel. It can send flow statistics and some information like video flow, position etc to contorl panel
package data

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"kuro/loader"
	pb "kuro/proto"
	"kuro/utils"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type DataClient struct {
	hostName string
	manager  *loader.EbpfManager
	client   pb.DataPlaneServiceClient
}

func NewDataClient(
	hostName string,
	manager *loader.EbpfManager,
	conn *grpc.ClientConn,
) *DataClient {
	return &DataClient{
		hostName: hostName,
		manager:  manager,
		client:   pb.NewDataPlaneServiceClient(conn),
	}
}

func (c *DataClient) Run(ctx context.Context) error {
	stream, err := c.client.StreamTrafficStats(ctx)
	if err != nil {
		return err
	}

	ticker := time.NewTicker(time.Second) // TODO: make this configurable
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = stream.CloseSend()
			return ctx.Err()

		case <-ticker.C:
			stats := c.manager.CollectStats()
			for _, s := range stats {

				nodeName, err := utils.NodeNameFromEth(s.IfaceName)
				if err != nil {
					return err
				}

				err = stream.Send(&pb.TrafficStats{
					NodeName:             nodeName,
					IfaceName:            s.IfaceName,
					TotalAcceptedBytes:   s.Stat.TotalAcceptedBytes,
					TotalDroppedBytes:    s.Stat.TotalDroppedBytes,
					TotalAcceptedPackets: s.Stat.TotalAcceptedPackets,
					TotalDroppedPackets:  s.Stat.TotalDroppedPackets,
					InstantRateBps:       s.Stat.InstantRateBps,
					SmoothRateBps:        s.Stat.SmoothRateBps,
					Timestamp:            s.Stat.TimeStamp.UnixMilli(),
				})
				if err != nil {
					return err
				}
			}
		}
	}
}

func RunDataClient(target, hostName string, manager *loader.EbpfManager) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// capture signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("received interrupt, shutting down...")
		cancel()
	}()

	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()

	dataClient := NewDataClient(hostName, manager, conn)
	return dataClient.Run(ctx)
}
