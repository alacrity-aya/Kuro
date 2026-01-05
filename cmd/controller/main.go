package main

import (
	"context"
	"log/slog"
	"os"

	pb "github.com/alacrity-aya/Kuro/api/proto/v1"
	"github.com/alacrity-aya/Kuro/internal/controller"
	"github.com/google/uuid"
)

func main() {
	slog.SetLogLoggerLevel(slog.LevelDebug)
	mgr := controller.NewControllerManager()
	defer mgr.Close()

	targetAgentAddr := "localhost:50051"

	req := &pb.EmulationRequest{
		RequestId:     uuid.New().String(),
		ConfigVersion: "v1.0.0",
		Workloads: []*pb.WorkloadEmulation{
			{
				PodName: "test-pod-nginx",
				RateLimit: &pb.RateLimit{
					RateBps:    10 * 1000 * 1000,
					BurstBytes: 1500 * 10,
				},
				Netem: &pb.Netem{
					DelayMs:  50,
					JitterMs: 10,
					LossPpm:  10000,
				},
			},
		},
	}

	resp, err := mgr.ApplyEmulationToAgent(context.Background(), targetAgentAddr, req)
	if err != nil {
		slog.Error("Failed to apply emulation", "error", err)
		os.Exit(1)
	}

	slog.Info("Response from agent",
		"status", resp.Status.String(),
		"message", resp.Message,
	)
	for _, res := range resp.Results {
		slog.Info("Workload result", "pod", res.PodName, "success", res.Success, "error", res.ErrorMessage)
	}
}
