package main

import (
	"flag"
	"log"
	"os"

	"kuro/internal/controller"

	ctrl "sigs.k8s.io/controller-runtime"
)

func main() {
	grpcPort := flag.Int("grpc-port", 9090, "Port for gRPC")
	httpPort := flag.Int("http-port", 8080, "Port for HTTP")
	metricsAddr := flag.String("metrics-bind-address", ":8082", "The address the metric endpoint binds to.")
	flag.Parse()

	mgr := controller.NewControllerManager(*grpcPort, *httpPort, *metricsAddr)

	ctx := ctrl.SetupSignalHandler()

	if err := mgr.Run(ctx); err != nil {
		log.Fatalf("Controller manager exited with error: %v", err)
		os.Exit(1)
	}
}
