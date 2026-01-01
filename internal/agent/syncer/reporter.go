package syncer

import (
	"context"
	"log/slog"
	"time"

	pb "github.com/alacrity-aya/Kuro/api/proto/v1"
)

type Reporter struct {
	client   pb.AgentServiceClient
	executor TaskExecutor
	agentID  string
}

func (r *Reporter) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.doReport(ctx)
		}
	}
}

func (r *Reporter) doReport(_ context.Context) {
	slog.Error("not implemented")
}
