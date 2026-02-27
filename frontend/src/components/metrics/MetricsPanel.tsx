import { BandwidthChart } from './BandwidthChart';
import { LatencyChart } from './LatencyChart';
import { PacketLossGauge } from './PacketLossGauge';
import type { LinkMetricsHistory, LinkMetrics } from '../../types/api';
import './MetricsPanel.css';

interface MetricsPanelProps {
  linkMetricsHistory?: LinkMetricsHistory;
  currentMetrics?: LinkMetrics;
  linkName?: string;
}

export function MetricsPanel({ 
  linkMetricsHistory, 
  currentMetrics,
  linkName 
}: MetricsPanelProps) {
  // If no data, show empty state
  if (!linkMetricsHistory && !currentMetrics) {
    return (
      <div className="metrics-panel metrics-panel--empty">
        <div className="metrics-panel__empty-icon">📊</div>
        <p className="metrics-panel__empty-text">
          Select a link to view metrics
        </p>
        <p className="metrics-panel__empty-hint">
          Click on a connection line in the topology to see performance data
        </p>
      </div>
    );
  }

  // Extract data from history or use defaults
  const bandwidthData = linkMetricsHistory?.bandwidth || [];
  const latencyData = linkMetricsHistory?.latency || [];
  const packetLossData = linkMetricsHistory?.packetLoss || [];
  
  // Get current packet loss from currentMetrics or latest history point
  const currentPacketLoss = currentMetrics?.packetLossRate ?? 
    (packetLossData.length > 0 ? packetLossData[packetLossData.length - 1].value : 0);

  // Calculate max values for chart scaling
  const maxBandwidth = Math.max(100, ...bandwidthData.map(d => d.value), 
    currentMetrics ? currentMetrics.bandwidthUsage : 0);
  const maxLatency = Math.max(100, ...latencyData.map(d => d.value),
    currentMetrics ? currentMetrics.currentLatency : 0);

  return (
    <div className="metrics-panel">
      {/* Header */}
      {linkName && (
        <div className="metrics-panel__header">
          <h3 className="metrics-panel__title">Link Metrics</h3>
          <span className="metrics-panel__link-name">{linkName}</span>
        </div>
      )}

      {/* Current Stats */}
      {currentMetrics && (
        <div className="metrics-panel__stats">
          <div className="metrics-stat">
            <span className="metrics-stat__label">Current BW</span>
            <span className="metrics-stat__value">
              {currentMetrics.bandwidthUsage.toFixed(1)} Mbps
            </span>
          </div>
          <div className="metrics-stat">
            <span className="metrics-stat__label">Latency</span>
            <span className="metrics-stat__value">
              {currentMetrics.currentLatency.toFixed(1)} ms
            </span>
          </div>
          <div className="metrics-stat">
            <span className="metrics-stat__label">Jitter</span>
            <span className="metrics-stat__value">
              {currentMetrics.currentJitter.toFixed(1)} ms
            </span>
          </div>
          <div className="metrics-stat">
            <span className="metrics-stat__label">Packets/s</span>
            <span className="metrics-stat__value">
              {currentMetrics.packetsPerSecond.toLocaleString()}
            </span>
          </div>
        </div>
      )}

      {/* Charts Grid */}
      <div className="metrics-panel__charts">
        {/* Packet Loss Gauge */}
        <div className="metrics-panel__chart metrics-panel__chart--gauge">
          <PacketLossGauge 
            value={currentPacketLoss} 
            title="Packet Loss"
            height={160}
          />
        </div>

        {/* Bandwidth Chart */}
        {bandwidthData.length > 0 && (
          <div className="metrics-panel__chart">
            <BandwidthChart 
              data={bandwidthData}
              title="Bandwidth History"
              maxBandwidth={Math.ceil(maxBandwidth / 10) * 10}
              height={180}
            />
          </div>
        )}

        {/* Latency Chart */}
        {latencyData.length > 0 && (
          <div className="metrics-panel__chart">
            <LatencyChart 
              data={latencyData}
              title="Latency History"
              maxLatency={Math.ceil(maxLatency / 10) * 10}
              height={180}
            />
          </div>
        )}
      </div>

      {/* Packet Loss History */}
      {packetLossData.length > 0 && (
        <div className="metrics-panel__history">
          <h4 className="metrics-panel__history-title">Packet Loss Trend</h4>
          <div className="metrics-panel__history-values">
            {packetLossData.slice(-10).map((point, idx) => (
              <span 
                key={idx} 
                className={`metrics-panel__history-value metrics-panel__history-value--${
                  point.value < 1 ? 'good' : point.value < 5 ? 'warning' : 'critical'
                }`}
              >
                {point.value.toFixed(2)}%
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
