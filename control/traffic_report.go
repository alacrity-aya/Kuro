package control

import (
	"context"
	"io"
	"log/slog"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "kuro/proto"
)

// ReportTraffic receive traffic from client
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

// define variables need to be uploaded to victoria metrics
var (
	// flow - bytes
	trafficAcceptedBytes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "traffic_accepted_bytes_total", Help: "Total accepted bytes",
	}, []string{"host", "node", "iface"})

	trafficDroppedBytes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "traffic_dropped_bytes_total", Help: "Total dropped bytes",
	}, []string{"host", "node", "iface"})

	// flow - packets
	trafficAcceptedPackets = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "traffic_accepted_packets_total", Help: "Total accepted packets",
	}, []string{"host", "node", "iface"})

	trafficDroppedPackets = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "traffic_dropped_packets_total", Help: "Total dropped packets",
	}, []string{"host", "node", "iface"})

	// rate
	trafficInstantRateBps = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "traffic_instant_rate_bps", Help: "Instantaneous rate in bps",
	}, []string{"host", "node", "iface"})

	trafficSmoothRateBps = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "traffic_smooth_rate_bps", Help: "Smoothed rate in bps",
	}, []string{"host", "node", "iface"})

	// 0: Offline, 1: Online
	agentOnlineStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "agent_online_status",
		Help: "Online status of the agent (1 for online, 0 for offline)",
	}, []string{"host"})
)

func init() {
	prometheus.MustRegister(
		trafficAcceptedBytes, trafficDroppedBytes,
		trafficAcceptedPackets, trafficDroppedPackets,
		trafficInstantRateBps, trafficSmoothRateBps,
		agentOnlineStatus,
	)
}

func (s *AgentServer) StartMetricsServer(ctx context.Context, addr string) {
	s.wg.Go(func() {
		slog.Info("Metrics worker started")
		for {
			select {
			case stat, ok := <-s.statsChan:
				if !ok {
					return
				}

				// extract labels
				lbls := prometheus.Labels{
					"host":  stat.HostName,
					"node":  stat.Stats.NodeName,
					"iface": stat.Stats.IfaceName,
				}

				// updata
				trafficAcceptedBytes.With(lbls).Set(float64(stat.Stats.TotalAcceptedBytes))
				trafficDroppedBytes.With(lbls).Set(float64(stat.Stats.TotalDroppedBytes))
				trafficAcceptedPackets.With(lbls).Set(float64(stat.Stats.TotalAcceptedPackets))
				trafficDroppedPackets.With(lbls).Set(float64(stat.Stats.TotalDroppedPackets))
				trafficInstantRateBps.With(lbls).Set(stat.Stats.InstantRateBps)
				trafficSmoothRateBps.With(lbls).Set(stat.Stats.SmoothRateBps)

			case <-ctx.Done():
				return
			}
		}
	})

	// start http service
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	srv := &http.Server{Addr: addr, Handler: mux}

	go func() {
		slog.Info("Metrics HTTP server listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Metrics server failed", "err", err)
		}
	}()

	go func() {
		<-ctx.Done()
		srv.Shutdown(context.Background())
	}()
}
