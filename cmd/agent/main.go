package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"kuro/internal/agent"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Configs
const (
	TargetNamespace = "kuro-experiment"
	ContainerSocket = "/run/containerd/containerd.sock"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		log.Println("Warning: NODE_NAME not set. Defaulting to 'kind-worker' for testing.")
		nodeName = "kind-worker"
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("HOME") + "/.kube/config"
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			log.Fatalf("Failed to build kubeconfig: %v", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create clientset: %v", err)
	}

	kuroAgent, err := agent.NewAgent(ContainerSocket, clientset, nodeName, TargetNamespace, "127.0.0.1")
	if err != nil {
		log.Fatalf("Failed to initialize agent: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log.Printf("Starting Kuro Agent on node [%s], watching namespace [%s]", nodeName, TargetNamespace)
	if err := kuroAgent.Run(ctx); err != nil {
		log.Fatalf("Agent exited with error: %v", err)
	}

	log.Println("Agent shutdown complete.")
}
