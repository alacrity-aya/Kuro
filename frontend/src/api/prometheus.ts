/**
 * Prometheus HTTP API 客户端
 * 文档: https://prometheus.io/docs/prometheus/latest/querying/api/
 * 
 * TODO: 需要配置 VITE_PROMETHEUS_URL 环境变量
 * 后端端点: Prometheus Service (NodePort 30091)
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
 * Prometheus HTTP API 客户端
 * 
 * 使用方式:
 * ```typescript
 * // 即时查询
 * const result = await prometheusClient.instantQuery('up');
 * 
 * // 范围查询
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
   * 即时查询
   * GET /api/v1/query?query=<query>
   * 
   * @param query - PromQL 查询表达式
   * @param options - 查询选项
   * @returns 查询结果
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
   * 范围查询
   * GET /api/v1/query_range?query=<query>&start=<start>&end=<end>&step=<step>
   * 
   * @param query - PromQL 查询表达式
   * @param options - 范围查询选项
   * @returns 查询结果
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
   * 获取标签值列表
   * GET /api/v1/label/<label>/values
   * 
   * @param label - 标签名称
   * @returns 标签值数组
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
   * 获取所有 metric 名称
   * GET /api/v1/label/__name__/values
   * 
   * @returns metric 名称数组
   */
  async getMetricNames(): Promise<string[]> {
    if (USE_MOCK) {
      const response = mockMetricNames();
      return response.data;
    }

    return this.getLabelValues('__name__');
  },

  /**
   * 获取 Kuro 相关的 Pod 列表
   * 
   * @returns Pod 名称数组
   */
  async getKuroPods(): Promise<string[]> {
    return this.getLabelValues('pod');
  },
};

// ============================================================================
// Predefined Queries for Kuro Metrics
// ============================================================================

/**
 * Kuro 预定义 PromQL 查询
 */
export const kuroQueries = {
  /**
   * 带宽查询
   */
  bandwidth: {
    /**
     * 各 Pod 下载带宽 (bytes/sec)
     * @param pod - Pod 名称，可选
     */
    downloadRate: (pod?: string) => 
      pod 
        ? `sum(rate(kuro_pod_traffic_bytes_total{direction="download",type="sim",pod="${pod}"}[5m]))`
        : `sum(rate(kuro_pod_traffic_bytes_total{direction="download",type="sim"}[5m])) by (pod)`,
    
    /**
     * 各 Pod 上传带宽 (bytes/sec)
     * @param pod - Pod 名称，可选
     */
    uploadRate: (pod?: string) => 
      pod 
        ? `sum(rate(kuro_pod_traffic_bytes_total{direction="upload",type="sim",pod="${pod}"}[5m]))`
        : `sum(rate(kuro_pod_traffic_bytes_total{direction="upload",type="sim"}[5m])) by (pod)`,
    
    /**
     * 总带宽 (bytes/sec)
     */
    totalRate: () => 
      `sum(rate(kuro_pod_traffic_bytes_total{type="sim"}[5m]))`,
  },

  /**
   * 延迟查询
   */
  latency: {
    /**
     * P50 延迟
     */
    p50: (pod?: string) => 
      pod
        ? `histogram_quantile(0.50, sum(rate(kuro_pod_latency_seconds_bucket{pod="${pod}"}[5m])) by (le))`
        : `histogram_quantile(0.50, sum(rate(kuro_pod_latency_seconds_bucket[5m])) by (pod, le))`,
    
    /**
     * P95 延迟
     */
    p95: (pod?: string) => 
      pod
        ? `histogram_quantile(0.95, sum(rate(kuro_pod_latency_seconds_bucket{pod="${pod}"}[5m])) by (le))`
        : `histogram_quantile(0.95, sum(rate(kuro_pod_latency_seconds_bucket[5m])) by (pod, le))`,
    
    /**
     * P99 延迟
     */
    p99: (pod?: string) => 
      pod
        ? `histogram_quantile(0.99, sum(rate(kuro_pod_latency_seconds_bucket{pod="${pod}"}[5m])) by (le))`
        : `histogram_quantile(0.99, sum(rate(kuro_pod_latency_seconds_bucket[5m])) by (pod, le))`,
    
    /**
     * 平均延迟
     */
    avg: (pod?: string) => 
      pod
        ? `rate(kuro_pod_latency_seconds_sum{pod="${pod}"}[5m]) / rate(kuro_pod_latency_seconds_count{pod="${pod}"}[5m])`
        : `rate(kuro_pod_latency_seconds_sum[5m]) / rate(kuro_pod_latency_seconds_count[5m])`,
  },

  /**
   * 丢包查询
   */
  packetLoss: {
    /**
     * 各 Pod 丢包率 (百分比)
     */
    rate: (pod?: string) => 
      pod
        ? `sum(rate(kuro_pod_drop_packets_total{pod="${pod}"}[5m])) / sum(rate(kuro_pod_traffic_packets_total{pod="${pod}"}[5m])) * 100`
        : `sum(rate(kuro_pod_drop_packets_total[5m])) by (pod) / sum(rate(kuro_pod_traffic_packets_total[5m])) by (pod) * 100`,
    
    /**
     * 总丢包数
     */
    total: () => 
      `sum(rate(kuro_pod_drop_packets_total[5m]))`,
  },

  /**
   * 流量统计
   */
  traffic: {
    /**
     * 总字节数
     */
    bytesTotal: (type: 'sim' | 'sys' = 'sim') => 
      `sum(kuro_pod_traffic_bytes_total{type="${type}"})`,
    
    /**
     * 总包数
     */
    packetsTotal: (type: 'sim' | 'sys' = 'sim') => 
      `sum(kuro_pod_traffic_packets_total{type="${type}"})`,
  },
};

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * 将 bytes/sec 转换为 Mbps
 */
export function bytesToMbps(bytesPerSec: number): number {
  return (bytesPerSec * 8) / 1_000_000;
}

/**
 * 将秒转换为毫秒
 */
export function secondsToMs(seconds: number): number {
  return seconds * 1000;
}

/**
 * 格式化带宽值
 */
export function formatBandwidth(bytesPerSec: number): string {
  const mbps = bytesToMbps(bytesPerSec);
  if (mbps >= 1000) {
    return `${(mbps / 1000).toFixed(2)} Gbps`;
  }
  return `${mbps.toFixed(2)} Mbps`;
}

/**
 * 格式化延迟值
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
 * 计算时间范围
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
