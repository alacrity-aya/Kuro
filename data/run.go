package data

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"kuro/loader"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

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
