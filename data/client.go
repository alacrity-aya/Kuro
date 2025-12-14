// Package data is kuro's data panel. It can send flow statistics and some information like video flow, position etc to contorl panel
package data

import (
	"context"
	"io"
	"log/slog"
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

	statsChan := make(chan *pb.TrafficStats, 1024)

	sendErrChan := make(chan error, 1)

	// consumer
	go func() {
		defer close(sendErrChan)
		for {
			select {
			case <-ctx.Done():
				_ = stream.CloseSend()
				return
			case stat, ok := <-statsChan:
				if !ok {
					_ = stream.CloseSend()
					return
				}
				if err := stream.Send(stat); err != nil {
					if err == io.EOF {
						slog.Warn("Stream closed by server")
					} else {
						slog.Error("Failed to send stats", "error", err)
					}
					// send err to producer to quit this function
					sendErrChan <- err
					return
				}
			}
		}
	}()

	// producer
	ticker := time.NewTicker(time.Second) // TODO: make configurable
	defer ticker.Stop()

	slog.Info("DataClient started", "host", c.hostName)

	for {
		select {
		// signal
		case <-ctx.Done():
			return ctx.Err()

		// receive err from consumer, quit this function
		case err := <-sendErrChan:
			return err

		case <-ticker.C:
			stats := c.manager.CollectStats()

			for _, s := range stats {
				nodeName, err := utils.NodeNameFromEth(s.IfaceName)
				if err != nil {
					slog.Warn("Failed to get node name", "iface", s.IfaceName, "error", err)
					continue
				}

				pbStat := &pb.TrafficStats{
					NodeName:             nodeName,
					IfaceName:            s.IfaceName,
					TotalAcceptedBytes:   s.Stat.TotalAcceptedBytes,
					TotalDroppedBytes:    s.Stat.TotalDroppedBytes,
					TotalAcceptedPackets: s.Stat.TotalAcceptedPackets,
					TotalDroppedPackets:  s.Stat.TotalDroppedPackets,
					InstantRateBps:       s.Stat.InstantRateBps,
					SmoothRateBps:        s.Stat.SmoothRateBps,
					Timestamp:            s.Stat.TimeStamp.UnixMilli(),
				}

				select {
				case statsChan <- pbStat:
				default:
					// buffer is full, drop statistic
					slog.Warn("Stats buffer full, dropping metric", "iface", s.IfaceName)
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
			dataClient := NewDataClient(hostName, manager, conn)

			if err := dataClient.Run(ctx); err != nil {
				slog.Error("DataClient run error (reconnecting...)", "error", err)
			}

			// close older connect, ready to reconnect
			_ = conn.Close()
			time.Sleep(2 * time.Second)
		}
	}
}
