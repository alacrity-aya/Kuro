/**
 * Metrics Page - Kuro Network Monitoring Dashboard
 * 
 * Integrates Prometheus metrics data display, including:
 * - Topology overview cards
 * - Bandwidth trend charts
 * - Latency distribution charts (P50/P95/P99)
 * - Packet loss monitoring
 * 
 * TODO: Requires backend API - Prometheus Service (NodePort 30091)
 */

import { useState, useCallback, useMemo, useEffect, useRef } from 'react';
import { SummaryCards } from '../components/metrics/SummaryCards';
import { BandwidthChart } from '../components/metrics/BandwidthChart';
import { LatencyChart, type LatencyDataPoint, type LatencyHistogramBin, aggregateLatencyData, generateHistogramFromBuckets } from '../components/metrics/LatencyChart';
import { PacketLossGauge } from '../components/metrics/PacketLossGauge';
import { TimeRangeSelector, calculateTimeRange, getRecommendedStep } from '../components/metrics/TimeRangeSelector';
import { RefreshControl } from '../components/metrics/RefreshControl';
import { PodSelector } from '../components/metrics/PodSelector';
import { GrafanaEmbed } from '../components/metrics/GrafanaEmbed';
import { useAutoRefresh } from '../hooks/useAutoRefresh';
import { prometheusClient, kuroQueries, bytesToMbps } from '../api/prometheus';
import type { MetricsSummary, TimeSeriesPoint } from '../types/api';
import type { RangeVector, InstantVector } from '../api/prometheus';
import './MetricsPage.css';

// ============================================================================
// Mock Data Generator for MetricsSummary
// ============================================================================

function generateMockMetricsSummary(): MetricsSummary {
  return {
    totalNodes: 7,
    runningNodes: 7,
    totalLinks: 10,
    activeLinks: 10,
    avgBandwidthMbps: 45 + Math.random() * 20,
    avgLatencyMs: 35 + Math.random() * 30,
    avgPacketLoss: 0.1 + Math.random() * 0.3,
    healthScore: 85 + Math.floor(Math.random() * 15),
  };
}

// ============================================================================
// Convert Prometheus data to TimeSeriesPoint
// ============================================================================

function aggregateTimeSeries(vectors: RangeVector[]): TimeSeriesPoint[] {
  if (vectors.length === 0) return [];
  
  // Use the first vector's timestamps as base
  const result: TimeSeriesPoint[] = [];
  const firstVector = vectors[0];
  
  firstVector.values.forEach(([timestamp], index) => {
    let sum = 0;
    let count = 0;
    
    vectors.forEach(vector => {
      if (vector.values[index]) {
        sum += parseFloat(vector.values[index][1]);
        count++;
      }
    });
    
    result.push({
      timestamp: timestamp * 1000,
      value: count > 0 ? sum / count : 0,
    });
  });
  
  return result;
}

// ============================================================================
// Generate Latency Data from Prometheus results
// ============================================================================

function generateLatencyData(
  p50Result: RangeVector[],
  p95Result: RangeVector[],
  p99Result: RangeVector[]
): LatencyDataPoint[] {
  if (p50Result.length === 0 || p95Result.length === 0 || p99Result.length === 0) {
    return [];
  }

  // Use first result from each query
  const p50Data = p50Result[0].values;
  const p95Data = p95Result[0].values;
  const p99Data = p99Result[0].values;

  return aggregateLatencyData(p50Data, p95Data, p99Data);
}

// ============================================================================
// Generate Histogram Bins from bucket data
// ============================================================================

function generateHistogramBins(bucketResult: InstantVector[]): LatencyHistogramBin[] {
  if (bucketResult.length === 0) return [];

  const buckets = bucketResult
    .filter(v => v.metric.le)
    .map(v => ({
      le: v.metric.le || '0',
      value: parseFloat(v.value[1]),
    }));

  return generateHistogramFromBuckets(buckets);
}

// ============================================================================
// Metrics Page Component
// ============================================================================

export default function MetricsPage() {
  // Get Grafana URL from environment
  const grafanaUrl = import.meta.env.VITE_GRAFANA_URL;

  // Time range state
  const [timeRange, setTimeRange] = useState('15m');
  
  // View mode state (charts or grafana)
  const [viewMode, setViewMode] = useState<'charts' | 'grafana'>('charts');
  
  // Pod selection state
  const [selectedPods, setSelectedPods] = useState<string[]>([]);
  const [availablePods, setAvailablePods] = useState<string[]>([]);
  const [isLoadingPods, setIsLoadingPods] = useState(false);
  
  // Metrics data state
  const [summaryData, setSummaryData] = useState<MetricsSummary | null>(null);
  const [bandwidthData, setBandwidthData] = useState<TimeSeriesPoint[]>([]);
  const [latencyData, setLatencyData] = useState<LatencyDataPoint[]>([]);
  const [latencyHistogramData, setLatencyHistogramData] = useState<LatencyHistogramBin[]>([]);
  const [packetLossData, setPacketLossData] = useState<{ [pod: string]: number }>({});
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // Track if pods have been initialized to avoid stale closure issues
  const podsInitializedRef = useRef(false);

  // Fetch available pods
  const fetchPods = useCallback(async () => {
    setIsLoadingPods(true);
    try {
      const pods = await prometheusClient.getKuroPods();
      setAvailablePods(pods);
      // Only set initial selection once
      if (!podsInitializedRef.current && pods.length > 0) {
        podsInitializedRef.current = true;
        setSelectedPods(pods);
      }
    } catch (err) {
      console.error('Failed to fetch pods:', err);
      // Fallback to mock pods
      const mockPods = ['drone-0', 'drone-1', 'drone-2', 'drone-3', 'drone-4', 
                        'ground-station-0', 'ground-station-1', 'gateway-0'];
      setAvailablePods(mockPods);
      if (!podsInitializedRef.current) {
        podsInitializedRef.current = true;
        setSelectedPods(mockPods);
      }
    } finally {
      setIsLoadingPods(false);
    }
  }, []); // No dependencies needed - using ref for initialization check

  // Fetch pods on mount
  useEffect(() => {
    fetchPods();
  }, [fetchPods]);

  // Fetch all metrics data
  const fetchMetrics = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    
    try {
      const { start, end } = calculateTimeRange(timeRange);
      const step = getRecommendedStep(timeRange);
      
      // Fetch latency percentiles in parallel with other metrics
      const [
        bandwidthResult,
        latencyP50Result,
        latencyP95Result,
        latencyP99Result,
        latencyBucketsResult,
        packetLossResult,
      ] = await Promise.all([
        // Bandwidth query - total sim traffic
        prometheusClient.rangeQuery(
          kuroQueries.bandwidth.totalRate(),
          { start, end, step }
        ),
        // Latency P50 query
        prometheusClient.rangeQuery(
          kuroQueries.latency.p50(),
          { start, end, step }
        ),
        // Latency P95 query
        prometheusClient.rangeQuery(
          kuroQueries.latency.p95(),
          { start, end, step }
        ),
        // Latency P99 query
        prometheusClient.rangeQuery(
          kuroQueries.latency.p99(),
          { start, end, step }
        ),
        // Latency histogram buckets for distribution view
        prometheusClient.instantQuery(
          `sum(rate(kuro_pod_latency_seconds_bucket[5m])) by (le)`
        ),
        // Packet loss query
        prometheusClient.instantQuery(kuroQueries.packetLoss.rate()),
      ]);
      
      // Process bandwidth data
      if (bandwidthResult.length > 0) {
        const aggregated = aggregateTimeSeries(bandwidthResult);
        // Convert bytes/sec to Mbps
        setBandwidthData(aggregated.map(p => ({
          ...p,
          value: bytesToMbps(p.value),
        })));
      }
      
      // Process latency data - P50/P95/P99
      const latencyPoints = generateLatencyData(
        latencyP50Result,
        latencyP95Result,
        latencyP99Result
      );
      setLatencyData(latencyPoints);

      // Process latency histogram data
      const histogramBins = generateHistogramBins(latencyBucketsResult);
      setLatencyHistogramData(histogramBins);
      
      // Process packet loss data - filter by selected pods
      const lossData: { [pod: string]: number } = {};
      packetLossResult.forEach((vector: InstantVector) => {
        const pod = vector.metric.pod;
        if (pod && (selectedPods.length === 0 || selectedPods.includes(pod))) {
          lossData[pod] = parseFloat(vector.value[1]);
        }
      });
      setPacketLossData(lossData);
      
      // Generate summary (from mock for now)
      setSummaryData({
        ...generateMockMetricsSummary(),
        totalNodes: selectedPods.length || availablePods.length,
        runningNodes: selectedPods.length || availablePods.length,
      });
      
    } catch (err) {
      console.error('Failed to fetch metrics:', err);
      setError(err instanceof Error ? err.message : 'Failed to fetch metrics');
      
      // Fallback to mock data on error
      setSummaryData(generateMockMetricsSummary());
      setBandwidthData(generateMockTimeSeries(30, 50, 15));
      setLatencyData(generateMockLatencyData(30));
      setLatencyHistogramData(generateMockHistogramBins());
      setPacketLossData({
        'drone-0': 0.12,
        'drone-1': 0.08,
        'drone-2': 0.15,
        'drone-3': 0.05,
        'drone-4': 0.10,
        'ground-station-0': 0.03,
        'ground-station-1': 0.02,
      });
    } finally {
      setIsLoading(false);
    }
  }, [timeRange, selectedPods, availablePods]);

  // Auto refresh hook
  const {
    interval: refreshInterval,
    setInterval: setRefreshInterval,
    enabled: autoRefreshEnabled,
    setEnabled: setAutoRefreshEnabled,
    refresh: manualRefresh,
    lastRefreshTime,
    isRefreshing,
  } = useAutoRefresh({
    onRefresh: fetchMetrics,
    initialInterval: 10000,
    initialEnabled: true,
  });

  // Fetch on time range or pod selection change
  useEffect(() => {
    if (selectedPods.length > 0) {
      fetchMetrics();
    }
  }, [fetchMetrics, selectedPods.length]);

  // Calculate average packet loss for gauge
  const avgPacketLoss = useMemo(() => {
    const values = Object.values(packetLossData);
    if (values.length === 0) return 0;
    return values.reduce((a, b) => a + b, 0) / values.length;
  }, [packetLossData]);

  return (
    <div className="metrics-page">
      {/* Header with controls */}
      <div className="metrics-page__header">
        <div className="metrics-page__header-left">
          <h1 className="metrics-page__title">Network Metrics</h1>
          {grafanaUrl && (
            <a
              href={grafanaUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="metrics-page__grafana-link"
            >
              <span className="metrics-page__grafana-icon">📊</span>
              Open Grafana
            </a>
          )}
        </div>
        
        <div className="metrics-page__controls">
          {/* View Mode Toggle */}
          <div className="metrics-page__control-group">
            <span className="metrics-page__control-label">View</span>
            <div className="metrics-page__view-toggle">
              <button
                className={`metrics-page__view-btn ${viewMode === 'charts' ? 'metrics-page__view-btn--active' : ''}`}
                onClick={() => setViewMode('charts')}
                title="Show charts view"
              >
                Charts
              </button>
              <button
                className={`metrics-page__view-btn ${viewMode === 'grafana' ? 'metrics-page__view-btn--active' : ''}`}
                onClick={() => setViewMode('grafana')}
                title="Show Grafana dashboard"
              >
                Grafana
              </button>
            </div>
          </div>
        
          {/* Pod Selector */}
          <div className="metrics-page__control-group">
            <span className="metrics-page__control-label">Pods</span>
            <PodSelector
              value={selectedPods}
              onChange={setSelectedPods}
              pods={availablePods}
              isLoading={isLoadingPods}
              disabled={isRefreshing}
            />
          </div>
          
          {/* Time Range Selector */}
          <div className="metrics-page__control-group">
            <span className="metrics-page__control-label">Time Range</span>
            <TimeRangeSelector
              value={timeRange}
              onChange={setTimeRange}
              disabled={isRefreshing}
            />
          </div>
          
          {/* Refresh Control */}
          <RefreshControl
            interval={refreshInterval}
            onIntervalChange={setRefreshInterval}
            enabled={autoRefreshEnabled}
            onEnabledChange={setAutoRefreshEnabled}
            onRefresh={manualRefresh}
            lastRefreshTime={lastRefreshTime}
            isRefreshing={isRefreshing}
          />
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div className="metrics-page__error">
          <span className="metrics-page__error-icon">⚠️</span>
          <span>{error}</span>
          <button onClick={fetchMetrics} className="metrics-page__error-retry">
            Retry
          </button>
        </div>
      )}

      {/* Summary Cards */}
      <section className="metrics-page__section metrics-page__section--summary">
        <SummaryCards data={summaryData} isLoading={isLoading} />
      </section>

      {/* Charts Grid - only show in charts mode */}
      {viewMode === 'charts' && (
        <section className="metrics-page__section metrics-page__section--charts">
        {/* Bandwidth Chart */}
        <div className="metrics-page__chart-container">
          <h2 className="metrics-page__chart-title">Bandwidth Trend</h2>
          <div className="metrics-page__chart">
            {bandwidthData.length > 0 ? (
              <BandwidthChart
                data={bandwidthData}
                title=""
                maxBandwidth={100}
                height={250}
              />
            ) : (
              <div className="metrics-page__chart-empty">
                No bandwidth data available
              </div>
            )}
          </div>
        </div>

        {/* Latency Chart - Enhanced with P50/P95/P99 */}
        <div className="metrics-page__chart-container">
          <h2 className="metrics-page__chart-title">Latency Distribution</h2>
          <div className="metrics-page__chart">
            {latencyData.length > 0 ? (
              <LatencyChart
                trendData={latencyData}
                histogramData={latencyHistogramData}
                title=""
                maxLatency={100}
                height={250}
                showViewToggle={true}
                darkMode={true}
                isLoading={isLoading}
              />
            ) : (
              <div className="metrics-page__chart-empty">
                No latency data available
              </div>
            )}
          </div>
        </div>

        {/* Packet Loss Gauges */}
        <div className="metrics-page__chart-container metrics-page__chart-container--loss">
          <h2 className="metrics-page__chart-title">Packet Loss by Pod</h2>
          <div className="metrics-page__gauges">
            {/* Average packet loss */}
            <div className="metrics-page__gauge-item">
              <PacketLossGauge
                value={avgPacketLoss}
                title="Average"
                height={140}
              />
            </div>
            
            {/* Per-pod packet loss - only show selected pods */}
            {selectedPods
              .filter(pod => packetLossData[pod] !== undefined)
              .slice(0, 4)
              .map(pod => (
                <div key={pod} className="metrics-page__gauge-item">
                  <PacketLossGauge
                    value={packetLossData[pod]}
                    title={pod}
                    height={140}
                  />
                </div>
              ))}
          </div>
        </div>
      </section>
      )}

      {/* Grafana Dashboard View - only show in grafana mode */}
      {viewMode === 'grafana' && (
        <section className="metrics-page__section metrics-page__section--grafana">
          <GrafanaEmbed
            dashboardUid="kuro-dashboard"
            refresh={`${refreshInterval / 1000}s`}
            theme="dark"
            height={600}
            title="Kuro Network Dashboard"
          />
        </section>
      )}

      {/* Info footer */}
      <div className="metrics-page__footer">
        <span className="metrics-page__footer-text">
          Data source: Prometheus metrics
        </span>
        <span className="metrics-page__footer-text">
          Refresh interval: {autoRefreshEnabled ? `${refreshInterval / 1000}s` : 'Paused'}
        </span>
      </div>
    </div>
  );
}

// ============================================================================
// Helper Functions
// ============================================================================

function generateMockTimeSeries(count: number, base: number, variance: number): TimeSeriesPoint[] {
  const now = Date.now();
  const interval = 60000; // 1 minute
  let currentValue = base;
  
  return Array.from({ length: count }, (_, i) => {
    const timestamp = now - (count - i - 1) * interval;
    const value = currentValue + (Math.random() - 0.5) * variance;
    currentValue = value;
    return { timestamp, value: Math.max(0, value) };
  });
}

function generateMockLatencyData(count: number): LatencyDataPoint[] {
  const now = Date.now();
  const interval = 60000; // 1 minute
  let p50 = 25;
  let p95 = 45;
  let p99 = 65;

  return Array.from({ length: count }, (_, i) => {
    const timestamp = now - (count - i - 1) * interval;
    // Random walk for each percentile
    p50 = Math.max(5, p50 + (Math.random() - 0.5) * 10);
    p95 = Math.max(p50 + 10, p95 + (Math.random() - 0.5) * 15);
    p99 = Math.max(p95 + 5, p99 + (Math.random() - 0.5) * 20);
    
    return { timestamp, p50, p95, p99 };
  });
}

function generateMockHistogramBins(): LatencyHistogramBin[] {
  return [
    { range: '0-10ms', count: 150, percentage: 15 },
    { range: '10-25ms', count: 320, percentage: 32 },
    { range: '25-50ms', count: 280, percentage: 28 },
    { range: '50-100ms', count: 180, percentage: 18 },
    { range: '100-250ms', count: 50, percentage: 5 },
    { range: '250-500ms', count: 15, percentage: 1.5 },
    { range: '500-1000ms', count: 5, percentage: 0.5 },
  ];
}