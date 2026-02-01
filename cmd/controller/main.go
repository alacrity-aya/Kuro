package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"kuro/internal/controller"
	"kuro/internal/controller/api"
)

func main() {
	// 1. Configuration Flags
	grpcPort := flag.Int("grpc-port", 9090, "Port for gRPC (Agent communication)")
	httpPort := flag.Int("http-port", 8080, "Port for HTTP (User/API communication)")
	flag.Parse()

	log.Printf("[Main] Starting Kuro Controller...")
	log.Printf("[Main] gRPC Port: %d | HTTP Port: %d", *grpcPort, *httpPort)

	// 2. Initialize Controller Manager (Core Domain + gRPC)
	mgr := controller.NewControllerManager(*grpcPort)

	// channel used to receive errors
	errCh := make(chan error, 2)

	// 3. Start gRPC Server
	go func() {
		log.Printf("[Main] Starting gRPC Server on :%d...", *grpcPort)
		if err := mgr.RunAgentServer(); err != nil {
			errCh <- err
		}
	}()

	// 4. Initialize & Start HTTP API Server
	httpServer := api.NewHTTPServer(mgr, *httpPort)
	go func() {
		log.Printf("[Main] Starting HTTP API Server on :%d...", *httpPort)
		if err := httpServer.Run(); err != nil {
			errCh <- err
		}
	}()

	// 5. Graceful Shutdown Handling
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		log.Fatalf("[Main] Service failed: %v", err)
	case sig := <-stopCh:
		log.Printf("[Main] Received signal %v, shutting down...", sig)
	}
}
