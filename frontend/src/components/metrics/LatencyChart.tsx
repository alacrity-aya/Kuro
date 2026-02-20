/**
 * LatencyChart - Latency Distribution Chart Component
 * 
 * Features:
 * - Supports P50/P95/P99 percentile latency trend chart
 * - Supports latency distribution histogram view
 * - Multi-Pod latency comparison
 * - Dark theme
 * 
 * PromQL queries:
 * - P50: histogram_quantile(0.50, rate(kuro_pod_latency_seconds_bucket[5m]))
 * - P95: histogram_quantile(0.95, rate(kuro_pod_latency_seconds_bucket[5m]))
 * - P99: histogram_quantile(0.99, rate(kuro_pod_latency_seconds_bucket[5m]))
 * 
 * TODO: Requires backend API - Prometheus Service (NodePort 30091)
 */

import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import * as echarts from 'echarts';
import type { EChartsOption } from 'echarts';
import type { TimeSeriesPoint } from '../../types/api';
import './LatencyChart.css';

// ============================================================================
// Types
// ============================================================================

export interface LatencyDataPoint {
  timestamp: number;
  p50: number;
  p95: number;
  p99: number;
}

export interface LatencyHistogramBin {
  range: string;
  count: number;
  percentage: number;
}

export interface LatencyChartProps {
  /** Trend data (new format, includes P50/P95/P99) */
  trendData?: LatencyDataPoint[];
  /** Single-value time series data (old format, backward compatible) */
  data?: TimeSeriesPoint[];
  /** Histogram data */
  histogramData?: LatencyHistogramBin[];
  /** Chart title */
  title?: string;
  /** Maximum latency value (ms) */
  maxLatency?: number;
  /** Chart height */
  height?: number;
  /** Initial view mode */
  defaultView?: 'trend' | 'histogram';
  /** Whether to show view toggle button */
  showViewToggle?: boolean;
  /** Whether dark theme */
  darkMode?: boolean;
  /** Selected percentiles */
  selectedPercentiles?: ('p50' | 'p95' | 'p99')[];
  /** Loading state */
  isLoading?: boolean;
  /** Multi-Pod trend data */
  multiPodTrendData?: Map<string, LatencyDataPoint[]>;
}

// ============================================================================
// Color Constants
// ============================================================================

const PERCENTILE_COLORS = {
  p50: { main: '#22c55e', light: 'rgba(34, 197, 94, 0.2)' },
  p95: { main: '#f59e0b', light: 'rgba(245, 158, 11, 0.2)' },
  p99: { main: '#ef4444', light: 'rgba(239, 68, 68, 0.2)' },
};

const DARK_COLORS = {
  background: '#1a1a2e',
  card: '#16213e',
  border: '#2a2a3e',
  text: '#e4e4e7',
  textSecondary: '#a1a1aa',
  grid: '#2a2a3e',
};

const LIGHT_COLORS = {
  background: '#ffffff',
  card: '#f8fafc',
  border: '#e2e8f0',
  text: '#1e293b',
  textSecondary: '#64748b',
  grid: '#e2e8f0',
};

// ============================================================================
// LatencyChart Component
// ============================================================================

export function LatencyChart({
  trendData,
  data,
  histogramData,
  title = 'Latency Distribution',
  maxLatency = 100,
  height = 250,
  defaultView = 'trend',
  showViewToggle = true,
  darkMode = true,
  selectedPercentiles = ['p50', 'p95', 'p99'],
  isLoading = false,
  multiPodTrendData,
}: LatencyChartProps) {
  const [viewMode, setViewMode] = useState<'trend' | 'histogram'>(defaultView);
  const chartRef = useRef<HTMLDivElement>(null);
  const chartInstance = useRef<echarts.ECharts | null>(null);

  const colors = darkMode ? DARK_COLORS : LIGHT_COLORS;
  
  // Backward compatibility: convert simple TimeSeriesPoint[] to LatencyDataPoint[]
  const normalizedTrendData = useMemo(() => {
    if (trendData && trendData.length > 0) {
      return trendData;
    }
    // If only 'data' is provided, treat all values as P95 (middle ground)
    if (data && data.length > 0) {
      return data.map(point => ({
        timestamp: point.timestamp,
        p50: point.value * 0.8,
        p95: point.value,
        p99: point.value * 1.2,
      }));
    }
    return null;
  }, [trendData, data]);

  // Handle resize
  const handleResize = useCallback(() => {
    chartInstance.current?.resize();
  }, []);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      chartInstance.current?.dispose();
      chartInstance.current = null;
    };
  }, []);

  // Render trend chart
  const renderTrendChart = useCallback(() => {
    if (!chartRef.current) return;

    if (!chartInstance.current) {
      chartInstance.current = echarts.init(chartRef.current, darkMode ? 'dark' : undefined);
    }

    // Multi-pod mode
    if (multiPodTrendData && multiPodTrendData.size > 0) {
      const series: echarts.LineSeriesOption[] = [];
      const podColors = ['#22c55e', '#3b82f6', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899'];
      let colorIndex = 0;

      multiPodTrendData.forEach((data, pod) => {
        if (data.length === 0) return;
        
        const color = podColors[colorIndex % podColors.length];
        colorIndex++;

        // Add P95 line for each pod
        series.push({
          name: `${pod} P95`,
          type: 'line',
          data: data.map(d => d.p95),
          smooth: true,
          symbol: 'none',
          lineStyle: { width: 2, color },
          areaStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: `${color}40` },
              { offset: 1, color: `${color}05` },
            ]),
          },
        });
      });

      const option: EChartsOption = {
        backgroundColor: 'transparent',
        tooltip: {
          trigger: 'axis',
          backgroundColor: colors.card,
          borderColor: colors.border,
          textStyle: { color: colors.text },
          formatter: (params: unknown) => {
            const p = params as Array<{ seriesName: string; axisValue: number; value: number }>;
            const date = new Date(p[0].axisValue);
            let html = `<div style="font-weight:600;margin-bottom:4px">${date.toLocaleTimeString()}</div>`;
            p.forEach(item => {
              html += `<div>${item.seriesName}: ${item.value.toFixed(2)} ms</div>`;
            });
            return html;
          },
        },
        legend: {
          show: true,
          top: 10,
          textStyle: { color: colors.textSecondary, fontSize: 11 },
          itemWidth: 12,
          itemHeight: 8,
        },
        grid: {
          left: 60,
          right: 20,
          top: 50,
          bottom: 30,
        },
        xAxis: {
          type: 'category',
          data: multiPodTrendData.values().next().value?.map(d => d.timestamp) || [],
          axisLabel: {
            formatter: (value: string | number) => {
              const date = new Date(Number(value));
              return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
            },
            fontSize: 10,
            color: colors.textSecondary,
          },
          axisLine: { lineStyle: { color: colors.border } },
          splitLine: { show: false },
        },
        yAxis: {
          type: 'value',
          name: 'ms',
          nameTextStyle: { fontSize: 10, color: colors.textSecondary },
          min: 0,
          max: maxLatency,
          axisLabel: { fontSize: 10, color: colors.textSecondary },
          splitLine: { lineStyle: { color: colors.grid, type: 'dashed' } },
        },
        series,
      };

      chartInstance.current.setOption(option, true);
      return;
    }

    // Single data source mode
    if (!normalizedTrendData || normalizedTrendData.length === 0) {
      chartInstance.current.clear();
      return;
    }

    const series: echarts.LineSeriesOption[] = [];

    if (selectedPercentiles.includes('p50')) {
      series.push({
        name: 'P50',
        type: 'line',
        data: normalizedTrendData.map(d => d.p50),
        smooth: true,
        symbol: 'none',
        lineStyle: { width: 2, color: PERCENTILE_COLORS.p50.main },
        areaStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: PERCENTILE_COLORS.p50.light },
            { offset: 1, color: 'transparent' },
          ]),
        },
      });
    }

    if (selectedPercentiles.includes('p95')) {
      series.push({
        name: 'P95',
        type: 'line',
        data: normalizedTrendData.map(d => d.p95),
        smooth: true,
        symbol: 'none',
        lineStyle: { width: 2, color: PERCENTILE_COLORS.p95.main },
        areaStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: PERCENTILE_COLORS.p95.light },
            { offset: 1, color: 'transparent' },
          ]),
        },
      });
    }

    if (selectedPercentiles.includes('p99')) {
      series.push({
        name: 'P99',
        type: 'line',
        data: normalizedTrendData.map(d => d.p99),
        smooth: true,
        symbol: 'none',
        lineStyle: { width: 2, color: PERCENTILE_COLORS.p99.main },
        areaStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: PERCENTILE_COLORS.p99.light },
            { offset: 1, color: 'transparent' },
          ]),
        },
      });
    }

    const option: EChartsOption = {
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'axis',
        backgroundColor: colors.card,
        borderColor: colors.border,
        textStyle: { color: colors.text },
        formatter: (params: unknown) => {
          const p = params as Array<{ seriesName: string; axisValue: number; value: number }>;
          const date = new Date(p[0].axisValue);
          let html = `<div style="font-weight:600;margin-bottom:4px">${date.toLocaleTimeString()}</div>`;
          p.forEach(item => {
            const color = PERCENTILE_COLORS[item.seriesName.toLowerCase() as keyof typeof PERCENTILE_COLORS]?.main || '#666';
            html += `<div><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${color};margin-right:6px"></span>${item.seriesName}: ${item.value.toFixed(2)} ms</div>`;
          });
          return html;
        },
      },
      legend: {
        show: true,
        top: 10,
        right: 10,
        textStyle: { color: colors.textSecondary, fontSize: 11 },
        itemWidth: 12,
        itemHeight: 8,
      },
      grid: {
        left: 60,
        right: 20,
        top: 40,
        bottom: 30,
      },
      xAxis: {
        type: 'category',
        data: normalizedTrendData.map(d => d.timestamp),
        axisLabel: {
          formatter: (value: string | number) => {
            const date = new Date(Number(value));
            return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
          },
          fontSize: 10,
          color: colors.textSecondary,
        },
        axisLine: { lineStyle: { color: colors.border } },
        splitLine: { show: false },
      },
      yAxis: {
        type: 'value',
        name: 'ms',
        nameTextStyle: { fontSize: 10, color: colors.textSecondary },
        min: 0,
        max: maxLatency,
        axisLabel: { fontSize: 10, color: colors.textSecondary },
        splitLine: { lineStyle: { color: colors.grid, type: 'dashed' } },
      },
      series,
    };

    chartInstance.current.setOption(option, true);
  }, [normalizedTrendData, multiPodTrendData, selectedPercentiles, maxLatency, darkMode, colors]);

  // Render histogram chart
  const renderHistogramChart = useCallback(() => {
    if (!chartRef.current || !histogramData || histogramData.length === 0) {
      chartInstance.current?.clear();
      return;
    }

    if (!chartInstance.current) {
      chartInstance.current = echarts.init(chartRef.current, darkMode ? 'dark' : undefined);
    }

    const option: EChartsOption = {
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'axis',
        backgroundColor: colors.card,
        borderColor: colors.border,
        textStyle: { color: colors.text },
        axisPointer: { type: 'shadow' },
        formatter: (params: unknown) => {
          const p = params as Array<{ name: string; value: number }>;
          const item = p[0];
          const bin = histogramData.find(b => b.range === item.name);
          return `<div style="font-weight:600">${item.name}</div>
                  <div>Count: ${item.value}</div>
                  <div>Percentage: ${bin?.percentage.toFixed(1)}%</div>`;
        },
      },
      grid: {
        left: 60,
        right: 20,
        top: 20,
        bottom: 40,
      },
      xAxis: {
        type: 'category',
        data: histogramData.map(d => d.range),
        axisLabel: {
          fontSize: 10,
          color: colors.textSecondary,
          rotate: 30,
        },
        axisLine: { lineStyle: { color: colors.border } },
      },
      yAxis: {
        type: 'value',
        name: 'Count',
        nameTextStyle: { fontSize: 10, color: colors.textSecondary },
        axisLabel: { fontSize: 10, color: colors.textSecondary },
        splitLine: { lineStyle: { color: colors.grid, type: 'dashed' } },
      },
      series: [
        {
          type: 'bar',
          data: histogramData.map((d) => ({
            value: d.count,
            itemStyle: {
              color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                { offset: 0, color: '#f59e0b' },
                { offset: 1, color: '#d97706' },
              ]),
              borderRadius: [4, 4, 0, 0],
            },
          })),
          barWidth: '70%',
        },
      ],
    };

    chartInstance.current.setOption(option, true);
  }, [histogramData, darkMode, colors]);

  // Resize event listener - separate from render effect to avoid re-binding
  useEffect(() => {
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [handleResize]);

  // Switch between views
  useEffect(() => {
    if (isLoading) return;

    if (viewMode === 'trend') {
      renderTrendChart();
    } else {
      renderHistogramChart();
    }
  }, [viewMode, renderTrendChart, renderHistogramChart, isLoading]);

  // Calculate summary stats
  const stats = useMemo(() => {
    if (!normalizedTrendData || normalizedTrendData.length === 0) return null;
    
    const last = normalizedTrendData[normalizedTrendData.length - 1];
    const avgP95 = normalizedTrendData.reduce((sum, d) => sum + d.p95, 0) / normalizedTrendData.length;
    const maxP99 = Math.max(...normalizedTrendData.map(d => d.p99));
    
    return {
      currentP50: last.p50,
      currentP95: last.p95,
      currentP99: last.p99,
      avgP95,
      maxP99,
    };
  }, [normalizedTrendData]);

  return (
    <div className={`latency-chart-container ${darkMode ? 'latency-chart--dark' : ''}`}>
      {/* Header */}
      <div className="latency-chart__header">
        <h3 className="latency-chart__title">{title}</h3>
        
        {showViewToggle && (
          <div className="latency-chart__view-toggle">
            <button
              className={`latency-chart__toggle-btn ${viewMode === 'trend' ? 'active' : ''}`}
              onClick={() => setViewMode('trend')}
            >
              Trend
            </button>
            <button
              className={`latency-chart__toggle-btn ${viewMode === 'histogram' ? 'active' : ''}`}
              onClick={() => setViewMode('histogram')}
            >
              Histogram
            </button>
          </div>
        )}
      </div>

      {/* Stats Row */}
      {stats && viewMode === 'trend' && (
        <div className="latency-chart__stats">
          <div className="latency-chart__stat latency-chart__stat--p50">
            <span className="latency-chart__stat-label">P50</span>
            <span className="latency-chart__stat-value">{stats.currentP50.toFixed(1)} ms</span>
          </div>
          <div className="latency-chart__stat latency-chart__stat--p95">
            <span className="latency-chart__stat-label">P95</span>
            <span className="latency-chart__stat-value">{stats.currentP95.toFixed(1)} ms</span>
          </div>
          <div className="latency-chart__stat latency-chart__stat--p99">
            <span className="latency-chart__stat-label">P99</span>
            <span className="latency-chart__stat-value">{stats.currentP99.toFixed(1)} ms</span>
          </div>
        </div>
      )}

      {/* Chart */}
      <div className="latency-chart__chart-wrapper">
        {isLoading ? (
          <div className="latency-chart__loading">
            <div className="latency-chart__spinner"></div>
            <span>Loading...</span>
          </div>
        ) : (
          <div
            ref={chartRef}
            className="latency-chart__chart"
            style={{ height: `${height}px` }}
          />
        )}
      </div>
    </div>
  );
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Generate histogram bins from Prometheus histogram data
 */
export function generateHistogramFromBuckets(
  buckets: Array<{ le: string; value: number }>
): LatencyHistogramBin[] {
  const sortedBuckets = buckets
    .filter(b => b.le !== '+Inf')
    .sort((a, b) => parseFloat(a.le) - parseFloat(b.le));

  const result: LatencyHistogramBin[] = [];
  let prevCount = 0;
  let totalCount = 0;

  // Calculate total count from +Inf bucket
  const infBucket = buckets.find(b => b.le === '+Inf');
  totalCount = infBucket?.value || 0;

  sortedBuckets.forEach((bucket, index) => {
    const count = bucket.value - prevCount;
    const leMs = parseFloat(bucket.le) * 1000; // Convert to ms
    const prevLeMs = index > 0 ? parseFloat(sortedBuckets[index - 1].le) * 1000 : 0;

    result.push({
      range: `${prevLeMs.toFixed(0)}-${leMs.toFixed(0)}ms`,
      count: Math.max(0, count),
      percentage: totalCount > 0 ? (Math.max(0, count) / totalCount) * 100 : 0,
    });

    prevCount = bucket.value;
  });

  return result;
}

/**
 * Generate LatencyDataPoint array from multiple time series data
 */
export function aggregateLatencyData(
  p50Data: Array<[number, string]>,
  p95Data: Array<[number, string]>,
  p99Data: Array<[number, string]>
): LatencyDataPoint[] {
  const result: LatencyDataPoint[] = [];
  const len = Math.min(p50Data.length, p95Data.length, p99Data.length);

  for (let i = 0; i < len; i++) {
    result.push({
      timestamp: p50Data[i][0] * 1000, // Convert to ms
      p50: parseFloat(p50Data[i][1]) * 1000, // Convert to ms
      p95: parseFloat(p95Data[i][1]) * 1000,
      p99: parseFloat(p99Data[i][1]) * 1000,
    });
  }

  return result;
}

export default LatencyChart;