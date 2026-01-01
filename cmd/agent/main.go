package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/alacrity-aya/Kuro/internal/agent"
	"github.com/alacrity-aya/Kuro/internal/agent/discovery"
	"github.com/alacrity-aya/Kuro/internal/agent/manager"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	criSocketPath = "unix:///run/containerd/containerd.sock"
	targetLabel   = "experiment-id"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kubeconfig := os.Getenv("KUBECONFIG")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		log.Fatalf("Error building kubeconfig: %v", err)
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

	manager := &manager.BpfManager{}

	containerAgent := agent.NewContainerAgent(watcher, manager)

	go func() {
		log.Println("🚀 Agent started, watching for pods...")
		containerAgent.Run(ctx)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")
}
