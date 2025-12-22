package control

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "kuro/proto"
)

// ReportTraffic placeholder
func (s *AgentServer) ReportTraffic(stream pb.AgentService_ReportTrafficServer) error {
	ctx := stream.Context()

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing metadata")
	}

	hostNames := md.Get("x-host-name")
	if len(hostNames) == 0 {
		return status.Error(codes.Unauthenticated, "x-host-name not found in metadata")
	}

	hostName := hostNames[0]

	info, exist := s.registry.GetInfo(hostName)

	if !exist || !info.online {
		slog.Warn("traffic report rejected: host not online", "host", hostName)
		return status.Errorf(codes.FailedPrecondition, "host %s is not online, please hello first", hostName)
	}

	slog.Info("started receiving traffic report", "host", hostName)

	for {
		stats, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.ReportAck{
				Ok:      true,
				Message: "stats received and processing",
			})
		}
		if err != nil {
			slog.Error("traffic stream error", "host", hostName, "err", err)
			return err
		}

		slog.Debug("get from stream", "stats", stats)

		select {
		case s.statsChan <- &ReportedStat{HostName: hostName, Stats: stats}:
		default:
			slog.Warn("stats channel full, dropping data", "host", hostName)
		}
	}
}

func (s *AgentServer) StartVMWorker(ctx context.Context, vmURL string) {
	writeURL := fmt.Sprintf("%s/write", vmURL)
	ticker := time.NewTicker(3 * time.Second)
	var batch []string
	const maxBatchSize = 1000

	s.wg.Go(func() {
		defer ticker.Stop()
		slog.Info("VictoriaMetrics worker started", "url", writeURL)
		for {
			select {
			case stat, ok := <-s.statsChan:
				if !ok {

					if len(batch) > 0 {
						s.sendToVM(writeURL, batch)
					}
					slog.Info("Worker: channel closed, final batch flushed")
					return
				}
				line := fmt.Sprintf("traffic,host=%s,node=%s,iface=%s accepted_bytes=%di,dropped_bytes=%di,rate_bps=%f %d",
					stat.HostName, stat.Stats.NodeName, stat.Stats.IfaceName,
					stat.Stats.TotalAcceptedBytes, stat.Stats.TotalDroppedBytes,
					stat.Stats.InstantRateBps, stat.Stats.Timestamp*1000000)
				batch = append(batch, line)

				if len(batch) >= maxBatchSize {
					s.sendToVM(writeURL, batch)
					batch = batch[:0]
				}

			case <-ticker.C:
				if len(batch) > 0 {
					s.sendToVM(writeURL, batch)
					batch = batch[:0]
				}

			case <-ctx.Done():
				if len(batch) > 0 {
					s.sendToVM(writeURL, batch)
				}
				slog.Info("Worker: context cancelled, flushing and exiting")
				return
			}
		}
	})
}

func (s *AgentServer) sendToVM(url string, lines []string) {
	body := strings.Join(lines, "\n")
	resp, err := http.Post(url, "text/plain", bytes.NewBufferString(body))
	if err != nil {
		slog.Error("failed to push data to VictoriaMetrics", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		slog.Warn("VM returned unexpected status", "code", resp.StatusCode)
	}
}
