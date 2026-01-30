package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"kuro/internal/controller"
)

func main() {
	// 1. Configuration Flags
	// Port 9090 matches the agent.yaml environment variable for the controller
	grpcPort := flag.Int("grpc-port", 9090, "Port for gRPC (Agent communication)")
	httpPort := flag.Int("http-port", 8080, "Port for HTTP (User/API communication)")
	flag.Parse()

	log.Printf("[Main] Starting Kuro Controller...")
	log.Printf("[Main] gRPC Port: %d | HTTP Port: %d", *grpcPort, *httpPort)

	// 2. Initialize Controller Manager
	mgr := controller.NewControllerManager(*grpcPort, *httpPort)

	// 3. Start the Manager (Non-blocking usually, but Run() in our design blocks on HTTP)
	// We run it in a goroutine to handle signals properly
	errCh := make(chan error, 1)
	go func() {
		if err := mgr.Run(); err != nil {
			errCh <- err
		}
	}()

	// 4. Graceful Shutdown Handling
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		log.Fatalf("[Main] Controller failed: %v", err)
	case sig := <-stopCh:
		log.Printf("[Main] Received signal %v, shutting down...", sig)
		// Logic to stop server gracefully could be added here
	}
}
