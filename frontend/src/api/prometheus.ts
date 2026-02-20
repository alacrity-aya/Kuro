/**
 * Prometheus HTTP API Client
 * Documentation: https://prometheus.io/docs/prometheus/latest/querying/api/
 * 
 * TODO: Requires VITE_PROMETHEUS_URL environment variable configuration
 * Backend endpoint: Prometheus Service (NodePort 30091)
 */

import {
  mockInstantQuery,
  mockRangeQuery,
  mockLabelValues,
  mockMetricNames,
  type PrometheusResponse,
  type InstantVector,
  type RangeVector,
  type InstantQueryResult,
  type RangeQueryResult,
} from './prometheusMock';

// ============================================================================
// Configuration
// ============================================================================

const PROMETHEUS_URL = import.meta.env.VITE_PROMETHEUS_URL || 'http://localhost:30091';
const USE_MOCK = import.meta.env.VITE_USE_MOCK_PROMETHEUS !== 'false'; // Default to mock

// ============================================================================
// Types
// ============================================================================

export type { 
  PrometheusResponse, 
  InstantVector, 
  RangeVector,
  InstantQueryResult,
  RangeQueryResult 
};

export interface QueryOptions {
  timeout?: string;  // Query timeout, e.g., "30s"
  time?: number;     // Evaluation timestamp (Unix timestamp)
}

export interface RangeQueryOptions extends QueryOptions {
  start: number;     // Start timestamp (Unix timestamp)
  end: number;       // End timestamp (Unix timestamp)
  step: string;      // Query resolution step width, e.g., "15s"
}

// ============================================================================
// Error Handling
// ============================================================================

export class PrometheusError extends Error {
  public readonly errorType?: string;
  
  constructor(message: string, errorType?: string) {
    super(message);
    this.name = 'PrometheusError';
    this.errorType = errorType;
  }
}

// ============================================================================
// Prometheus Client
// ============================================================================

/**
 * Prometheus HTTP API Client
 * 
 * Usage:
 * ```typescript
 * // Instant query
 * const result = await prometheusClient.instantQuery('up');
 * 
 * // Range query
 * const rangeResult = await prometheusClient.rangeQuery({
 *   query: 'rate(http_requests_total[5m])',
 *   start: Date.now() / 1000 - 3600,
 *   end: Date.now() / 1000,
 *   step: '15s'
 * });
 * ```
 */
export const prometheusClient = {
  /**
   * Instant query
   * GET /api/v1/query?query=<query>
   * 
   * @param query - PromQL query expression
   * @param options - Query options
   * @returns Query result
   */
  async instantQuery(
    query: string, 
    options?: QueryOptions
  ): Promise<InstantVector[]> {
    if (USE_MOCK) {
      const response = mockInstantQuery(query);
      if (response.status === 'error') {
        throw new PrometheusError(response.error || 'Unknown error', response.errorType);
      }
      return response.data.result;
    }

    const params = new URLSearchParams({ query });
    if (options?.timeout) params.set('timeout', options.timeout);
    if (options?.time) params.set('time', options.time.toString());

    const response = await fetch(`${PROMETHEUS_URL}/api/v1/query?${params}`);
    
    if (!response.ok) {
      throw new PrometheusError(`HTTP error: ${response.status} ${response.statusText}`);
    }

    const json: PrometheusResponse<InstantQueryResult> = await response.json();
    
    if (json.status === 'error') {
      throw new PrometheusError(json.error || 'Unknown error', json.errorType);
    }

    return json.data.result;
  },

  /**
   * Range query
   * GET /api/v1/query_range?query=<query>&start=<start>&end=<end>&step=<step>
   * 
   * @param query - PromQL query expression
   * @param options - Range query options
   * @returns Query result
   */
  async rangeQuery(
    query: string,
    options: RangeQueryOptions
  ): Promise<RangeVector[]> {
    if (USE_MOCK) {
      const response = mockRangeQuery(query, options.start, options.end, options.step);
      if (response.status === 'error') {
        throw new PrometheusError(response.error || 'Unknown error', response.errorType);
      }
      return response.data.result;
    }

    const params = new URLSearchParams({
      query,
      start: options.start.toString(),
      end: options.end.toString(),
      step: options.step,
    });
    
    if (options.timeout) params.set('timeout', options.timeout);

    const response = await fetch(`${PROMETHEUS_URL}/api/v1/query_range?${params}`);
    
    if (!response.ok) {
      throw new PrometheusError(`HTTP error: ${response.status} ${response.statusText}`);
    }

    const json: PrometheusResponse<RangeQueryResult> = await response.json();
    
    if (json.status === 'error') {
      throw new PrometheusError(json.error || 'Unknown error', json.errorType);
    }

    return json.data.result;
  },

  /**
   * Get label values list
   * GET /api/v1/label/<label>/values
   * 
   * @param label - Label name
   * @returns Label values array
   */
  async getLabelValues(label: string): Promise<string[]> {
    if (USE_MOCK) {
      const response = mockLabelValues(label);
      return response.data;
    }

    const response = await fetch(`${PROMETHEUS_URL}/api/v1/label/${label}/values`);
    
    if (!response.ok) {
      throw new PrometheusError(`HTTP error: ${response.status} ${response.statusText}`);
    }

    const json: PrometheusResponse<string[]> = await response.json();
    
    if (json.status === 'error') {
      throw new PrometheusError(json.error || 'Unknown error', json.errorType);
    }

    return json.data;
  },

  /**
   * Get all metric names
   * GET /api/v1/label/__name__/values
   * 
   * @returns Metric names array
   */
  async getMetricNames(): Promise<string[]> {
    if (USE_MOCK) {
      const response = mockMetricNames();
      return response.data;
    }

    return this.getLabelValues('__name__');
  },

  /**
   * Get Kuro-related Pod list
   * 
   * @returns Pod names array
   */
  async getKuroPods(): Promise<string[]> {
    return this.getLabelValues('pod');
  },
};

// ============================================================================
// Predefined Queries for Kuro Metrics
// ============================================================================

/**
 * Kuro predefined PromQL queries
 */
export const kuroQueries = {
  /**
   * Bandwidth queries
   */
  bandwidth: {
    /**
     * Per-Pod download bandwidth (bytes/sec)
     * @param pod - Pod name, optional
     */
    downloadRate: (pod?: string) => 
      pod 
        ? `sum(rate(kuro_pod_traffic_bytes_total{direction="download",type="sim",pod="${pod}"}[5m]))`
        : `sum(rate(kuro_pod_traffic_bytes_total{direction="download",type="sim"}[5m])) by (pod)`,
    
    /**
     * Per-Pod upload bandwidth (bytes/sec)
     * @param pod - Pod name, optional
     */
    uploadRate: (pod?: string) => 
      pod 
        ? `sum(rate(kuro_pod_traffic_bytes_total{direction="upload",type="sim",pod="${pod}"}[5m]))`
        : `sum(rate(kuro_pod_traffic_bytes_total{direction="upload",type="sim"}[5m])) by (pod)`,
    
    /**
     * Total bandwidth (bytes/sec)
     */
    totalRate: () => 
      `sum(rate(kuro_pod_traffic_bytes_total{type="sim"}[5m]))`,
  },

  /**
   * Latency queries
   */
  latency: {
    /**
     * P50 latency
     */
    p50: (pod?: string) => 
      pod
        ? `histogram_quantile(0.50, sum(rate(kuro_pod_latency_seconds_bucket{pod="${pod}"}[5m])) by (le))`
        : `histogram_quantile(0.50, sum(rate(kuro_pod_latency_seconds_bucket[5m])) by (pod, le))`,
    
    /**
     * P95 latency
     */
    p95: (pod?: string) => 
      pod
        ? `histogram_quantile(0.95, sum(rate(kuro_pod_latency_seconds_bucket{pod="${pod}"}[5m])) by (le))`
        : `histogram_quantile(0.95, sum(rate(kuro_pod_latency_seconds_bucket[5m])) by (pod, le))`,
    
    /**
     * P99 latency
     */
    p99: (pod?: string) => 
      pod
        ? `histogram_quantile(0.99, sum(rate(kuro_pod_latency_seconds_bucket{pod="${pod}"}[5m])) by (le))`
        : `histogram_quantile(0.99, sum(rate(kuro_pod_latency_seconds_bucket[5m])) by (pod, le))`,
    
    /**
     * Average latency
     */
    avg: (pod?: string) => 
      pod
        ? `rate(kuro_pod_latency_seconds_sum{pod="${pod}"}[5m]) / rate(kuro_pod_latency_seconds_count{pod="${pod}"}[5m])`
        : `rate(kuro_pod_latency_seconds_sum[5m]) / rate(kuro_pod_latency_seconds_count[5m])`,
  },

  /**
   * Packet loss queries
   */
  packetLoss: {
    /**
     * Per-Pod packet loss rate (percentage)
     */
    rate: (pod?: string) => 
      pod
        ? `sum(rate(kuro_pod_drop_packets_total{pod="${pod}"}[5m])) / sum(rate(kuro_pod_traffic_packets_total{pod="${pod}"}[5m])) * 100`
        : `sum(rate(kuro_pod_drop_packets_total[5m])) by (pod) / sum(rate(kuro_pod_traffic_packets_total[5m])) by (pod) * 100`,
    
    /**
     * Total packet drops
     */
    total: () => 
      `sum(rate(kuro_pod_drop_packets_total[5m]))`,
  },

  /**
   * Traffic statistics
   */
  traffic: {
    /**
     * Total bytes
     */
    bytesTotal: (type: 'sim' | 'sys' = 'sim') => 
      `sum(kuro_pod_traffic_bytes_total{type="${type}"})`,
    
    /**
     * Total packets
     */
    packetsTotal: (type: 'sim' | 'sys' = 'sim') => 
      `sum(kuro_pod_traffic_packets_total{type="${type}"})`,
  },
};

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Convert bytes/sec to Mbps
 */
export function bytesToMbps(bytesPerSec: number): number {
  return (bytesPerSec * 8) / 1_000_000;
}

/**
 * Convert seconds to milliseconds
 */
export function secondsToMs(seconds: number): number {
  return seconds * 1000;
}

/**
 * Format bandwidth value
 */
export function formatBandwidth(bytesPerSec: number): string {
  const mbps = bytesToMbps(bytesPerSec);
  if (mbps >= 1000) {
    return `${(mbps / 1000).toFixed(2)} Gbps`;
  }
  return `${mbps.toFixed(2)} Mbps`;
}

/**
 * Format latency value
 */
export function formatLatency(seconds: number): string {
  if (seconds < 0.001) {
    return `${(seconds * 1_000_000).toFixed(2)} μs`;
  }
  if (seconds < 1) {
    return `${(seconds * 1000).toFixed(2)} ms`;
  }
  return `${seconds.toFixed(2)} s`;
}

/**
 * Calculate time range
 */
export function getTimeRange(duration: string): { start: number; end: number } {
  const now = Math.floor(Date.now() / 1000);
  const match = duration.match(/^(\d+)(m|h|d)$/);
  
  if (!match) {
    return { start: now - 300, end: now }; // Default 5m
  }
  
  const [, value, unit] = match;
  const multipliers: Record<string, number> = { m: 60, h: 3600, d: 86400 };
  const offset = parseInt(value) * multipliers[unit];
  
  return { start: now - offset, end: now };
}
