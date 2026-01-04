package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/alacrity-aya/Kuro/internal/agent"
	"github.com/alacrity-aya/Kuro/internal/agent/discovery"
	"github.com/alacrity-aya/Kuro/internal/agent/manager"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	criSocketPath = "unix:///run/containerd/containerd.sock"
	targetLabel   = "experiment-id"
)

func main() {
	slog.SetLogLoggerLevel(slog.LevelDebug)
	ctx, cancel := context.WithCancel(context.Background())

	kubeconfig := os.Getenv("KUBECONFIG")
	var config *rest.Config
	var err error

	if kubeconfig != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			log.Printf("Error building kubeconfig from file: %v, trying in-cluster config", err)
		}
	}

	if config == nil {
		config, err = rest.InClusterConfig()
		if err != nil {
			log.Fatalf("Error building kubernetes client config: %v", err)
		}
	}
	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Error building kubernetes client: %v", err)
	}

	watcher, err := discovery.NewPodWatcher(k8sClient, criSocketPath, targetLabel)
	if err != nil {
		log.Fatalf("Failed to create pod watcher: %v", err)
	}
	defer watcher.Close()

	manager := manager.NewBpfManager()

	containerAgent := agent.NewContainerAgent(watcher, manager)
	defer containerAgent.Close()

	go func() {
		log.Println("🚀 Agent started, watching for pods...")
		containerAgent.Run(ctx, ":50051")
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	cancel()

	log.Println("Shutting down...")
}
