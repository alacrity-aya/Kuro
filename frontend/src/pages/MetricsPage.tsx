/**
 * Metrics Page - Kuro Network Monitoring Dashboard
 * 
 * 整合 Prometheus metrics 数据展示，包括：
 * - 拓扑概览卡片
 * - 带宽趋势图表
 * - 延迟分布图表
 * - 丢包率监控
 * 
 * TODO: 需要后端 API - Prometheus Service (NodePort 30091)
 */

import { useState, useCallback, useMemo, useEffect } from 'react';
import { SummaryCards } from '../components/metrics/SummaryCards';
import { BandwidthChart } from '../components/metrics/BandwidthChart';
import { LatencyChart } from '../components/metrics/LatencyChart';
import { PacketLossGauge } from '../components/metrics/PacketLossGauge';
import { TimeRangeSelector, calculateTimeRange, getRecommendedStep } from '../components/metrics/TimeRangeSelector';
import { RefreshControl } from '../components/metrics/RefreshControl';
import { PodSelector } from '../components/metrics/PodSelector';
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
// Metrics Page Component
// ============================================================================

export default function MetricsPage() {
  // Time range state
  const [timeRange, setTimeRange] = useState('15m');
  
  // Pod selection state
  const [selectedPods, setSelectedPods] = useState<string[]>([]);
  const [availablePods, setAvailablePods] = useState<string[]>([]);
  const [isLoadingPods, setIsLoadingPods] = useState(false);
  
  // Metrics data state
  const [summaryData, setSummaryData] = useState<MetricsSummary | null>(null);
  const [bandwidthData, setBandwidthData] = useState<TimeSeriesPoint[]>([]);
  const [latencyData, setLatencyData] = useState<TimeSeriesPoint[]>([]);
  const [packetLossData, setPacketLossData] = useState<{ [pod: string]: number }>({});
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Fetch available pods
  const fetchPods = useCallback(async () => {
    setIsLoadingPods(true);
    try {
      const pods = await prometheusClient.getKuroPods();
      setAvailablePods(pods);
      // If no pods selected yet, select all by default
      if (selectedPods.length === 0 && pods.length > 0) {
        setSelectedPods(pods);
      }
    } catch (err) {
      console.error('Failed to fetch pods:', err);
      // Fallback to mock pods
      const mockPods = ['drone-0', 'drone-1', 'drone-2', 'drone-3', 'drone-4', 
                        'ground-station-0', 'ground-station-1', 'gateway-0'];
      setAvailablePods(mockPods);
      if (selectedPods.length === 0) {
        setSelectedPods(mockPods);
      }
    } finally {
      setIsLoadingPods(false);
    }
  }, [selectedPods.length]);

  // Fetch pods on mount
  useEffect(() => {
    fetchPods();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Fetch all metrics data
  const fetchMetrics = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    
    try {
      const { start, end } = calculateTimeRange(timeRange);
      const step = getRecommendedStep(timeRange);
      
      // Fetch data in parallel
      const [bandwidthResult, latencyResult, packetLossResult] = await Promise.all([
        // Bandwidth query - total sim traffic
        prometheusClient.rangeQuery(
          kuroQueries.bandwidth.totalRate(),
          { start, end, step }
        ),
        // Latency query - average
        prometheusClient.rangeQuery(
          kuroQueries.latency.avg(),
          { start, end, step }
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
      
      // Process latency data (convert seconds to milliseconds)
      if (latencyResult.length > 0) {
        const aggregated = aggregateTimeSeries(latencyResult);
        setLatencyData(aggregated.map(p => ({
          ...p,
          value: p.value * 1000, // sec to ms
        })));
      }
      
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
      setLatencyData(generateMockTimeSeries(30, 45, 10));
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
  }, [timeRange, selectedPods]); // eslint-disable-line react-hooks/exhaustive-deps

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
        <h1 className="metrics-page__title">Network Metrics</h1>
        
        <div className="metrics-page__controls">
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

      {/* Charts Grid */}
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

        {/* Latency Chart */}
        <div className="metrics-page__chart-container">
          <h2 className="metrics-page__chart-title">Latency Trend</h2>
          <div className="metrics-page__chart">
            {latencyData.length > 0 ? (
              <LatencyChart
                data={latencyData}
                title=""
                maxLatency={100}
                height={250}
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
