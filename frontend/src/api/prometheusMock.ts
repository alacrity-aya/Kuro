/**
 * Mock Prometheus API Response
 * Format reference: https://prometheus.io/docs/prometheus/latest/querying/api/
 * 
 * TODO: Requires backend API - Prometheus Service (NodePort 30091)
 */

// ============================================================================
// Types
// ============================================================================

export interface PrometheusResponse<T> {
  status: 'success' | 'error';
  data: T;
  error?: string;
  errorType?: string;
}

export interface InstantVector {
  metric: Record<string, string>;
  value: [number, string]; // [timestamp, value]
}

export interface RangeVector {
  metric: Record<string, string>;
  values: Array<[number, string]>; // [[timestamp, value], ...]
}

export interface InstantQueryResult {
  resultType: 'vector';
  result: InstantVector[];
}

export interface RangeQueryResult {
  resultType: 'matrix';
  result: RangeVector[];
}

// ============================================================================
// Mock Data
// ============================================================================

const MOCK_PODS = ['drone-0', 'drone-1', 'drone-2', 'drone-3', 'drone-4', 
                   'ground-station-0', 'ground-station-1', 'gateway-0'];
const DIRECTIONS = ['download', 'upload'] as const;
const TRAFFIC_TYPES = ['sim', 'sys'] as const;

// Latency histogram buckets (in seconds)
const LATENCY_BUCKETS = ['0.001', '0.005', '0.01', '0.025', '0.05', '0.1', '0.25', '0.5', '1', '+Inf'];

// ============================================================================
// Helper Functions
// ============================================================================

function parseDuration(d: string): number {
  const match = d.match(/^(\d+)(s|m|h)$/);
  if (!match) return 15;
  const [, n, unit] = match;
  const multipliers: Record<string, number> = { s: 1, m: 60, h: 3600 };
  return parseInt(n) * multipliers[unit];
}

function generateWalkValue(previous: number, step: number, min: number = 0): number {
  const change = (Math.random() - 0.5) * step;
  return Math.max(min, previous + change);
}

// ============================================================================
// Mock Instant Query
// ============================================================================

/**
 * Mock Prometheus instant query
 * GET /api/v1/query?query=<query>
 */
export function mockInstantQuery(query: string): PrometheusResponse<InstantQueryResult> {
  const now = Math.floor(Date.now() / 1000);

  // Traffic bytes query
  if (query.includes('kuro_pod_traffic_bytes_total')) {
    const results: InstantVector[] = [];
    
    MOCK_PODS.forEach(pod => {
      DIRECTIONS.forEach(direction => {
        TRAFFIC_TYPES.forEach(type => {
          // Sim traffic has higher values
          const baseBytes = type === 'sim' ? 1e6 + Math.random() * 5e6 : 1e5 + Math.random() * 5e5;
          results.push({
            metric: { pod, direction, type },
            value: [now, baseBytes.toFixed(2)]
          });
        });
      });
    });

    return {
      status: 'success',
      data: { resultType: 'vector', result: results }
    };
  }

  // Traffic packets query
  if (query.includes('kuro_pod_traffic_packets_total')) {
    const results: InstantVector[] = [];
    
    MOCK_PODS.forEach(pod => {
      DIRECTIONS.forEach(direction => {
        TRAFFIC_TYPES.forEach(type => {
          const basePackets = type === 'sim' ? 5000 + Math.random() * 10000 : 500 + Math.random() * 1000;
          results.push({
            metric: { pod, direction, type },
            value: [now, basePackets.toFixed(0)]
          });
        });
      });
    });

    return {
      status: 'success',
      data: { resultType: 'vector', result: results }
    };
  }

  // Drop packets query
  if (query.includes('kuro_pod_drop_packets_total')) {
    const results: InstantVector[] = [];
    
    MOCK_PODS.forEach(pod => {
      DIRECTIONS.forEach(direction => {
        TRAFFIC_TYPES.forEach(type => {
          // Lower drop rate for system traffic
          const baseDrops = type === 'sim' ? Math.random() * 50 : Math.random() * 5;
          results.push({
            metric: { pod, direction, type },
            value: [now, baseDrops.toFixed(0)]
          });
        });
      });
    });

    return {
      status: 'success',
      data: { resultType: 'vector', result: results }
    };
  }

  // Drop bytes query
  if (query.includes('kuro_pod_drop_bytes_total')) {
    const results: InstantVector[] = [];
    
    MOCK_PODS.forEach(pod => {
      DIRECTIONS.forEach(direction => {
        TRAFFIC_TYPES.forEach(type => {
          const baseBytes = type === 'sim' ? Math.random() * 50000 : Math.random() * 5000;
          results.push({
            metric: { pod, direction, type },
            value: [now, baseBytes.toFixed(2)]
          });
        });
      });
    });

    return {
      status: 'success',
      data: { resultType: 'vector', result: results }
    };
  }

  // Latency percentile instant query (histogram_quantile)
  if (query.includes('histogram_quantile') && query.includes('kuro_pod_latency_seconds_bucket')) {
    const results: InstantVector[] = [];
    
    // Extract quantile from query
    const quantileMatch = query.match(/histogram_quantile\((\d+\.?\d*)/);
    const quantile = quantileMatch ? parseFloat(quantileMatch[1]) : 0.95;
    
    // Base latency depends on quantile
    const baseLatency = 0.02 + (quantile * 0.05);
    
    // Check if aggregating by pod
    const hasByPod = query.includes('by (pod');
    
    if (hasByPod) {
      MOCK_PODS.forEach(pod => {
        const latency = baseLatency + Math.random() * 0.02;
        results.push({
          metric: { pod },
          value: [now, latency.toFixed(6)]
        });
      });
    } else {
      // Check if aggregating by le (for histogram buckets)
      const hasByLe = query.includes('by (le)');
      if (hasByLe) {
        // Return bucket aggregation for histogram view
        LATENCY_BUCKETS.forEach(le => {
          const bucketValue = le === '+Inf' ? 1000 : parseFloat(le) * 500 * (1 + Math.random());
          results.push({
            metric: { le },
            value: [now, bucketValue.toFixed(0)]
          });
        });
      } else {
        // Single result
        results.push({
          metric: {},
          value: [now, (baseLatency + Math.random() * 0.02).toFixed(6)]
        });
      }
    }
    
    return {
      status: 'success',
      data: { resultType: 'vector', result: results }
    };
  }

  // Latency histogram bucket query
  if (query.includes('kuro_pod_latency_seconds_bucket')) {
    const results: InstantVector[] = [];
    
    // Check if this is an aggregation query (for histogram bins)
    const isAggregated = query.includes('sum(') && query.includes('by (le)');
    
    if (isAggregated) {
      // Return aggregated buckets for histogram display
      LATENCY_BUCKETS.forEach(le => {
        const bucketValue = le === '+Inf' ? 1000 : parseFloat(le) * 500 * (1 + Math.random());
        results.push({
          metric: { le },
          value: [now, bucketValue.toFixed(0)]
        });
      });
    } else {
      // Per-pod bucket data
      MOCK_PODS.forEach(pod => {
        LATENCY_BUCKETS.forEach(le => {
          const bucketValue = le === '+Inf' ? 1000 : parseFloat(le) * 1000 * (1 + Math.random());
          results.push({
            metric: { pod, le },
            value: [now, bucketValue.toFixed(0)]
          });
        });
      });
    }

    return {
      status: 'success',
      data: { resultType: 'vector', result: results }
    };
  }

  // Latency count/sum query
  if (query.includes('kuro_pod_latency_seconds_count')) {
    const results: InstantVector[] = MOCK_PODS.map(pod => ({
      metric: { pod },
      value: [now, (5000 + Math.random() * 5000).toFixed(0)]
    }));

    return {
      status: 'success',
      data: { resultType: 'vector', result: results }
    };
  }

  if (query.includes('kuro_pod_latency_seconds_sum')) {
    const results: InstantVector[] = MOCK_PODS.map(pod => ({
      metric: { pod },
      value: [now, (100 + Math.random() * 50).toFixed(2)]
    }));

    return {
      status: 'success',
      data: { resultType: 'vector', result: results }
    };
  }

  // Default empty result
  return {
    status: 'success',
    data: { resultType: 'vector', result: [] }
  };
}

// ============================================================================
// Mock Range Query
// ============================================================================

/**
 * Mock Prometheus range query
 * GET /api/v1/query_range?query=<query>&start=<start>&end=<end>&step=<step>
 */
export function mockRangeQuery(
  query: string,
  start: number,
  end: number,
  step: string = '15s'
): PrometheusResponse<RangeQueryResult> {
  const stepSeconds = parseDuration(step);
  const pointCount = Math.min(500, Math.floor((end - start) / stepSeconds) + 1);

  // Traffic bytes query
  if (query.includes('kuro_pod_traffic_bytes_total')) {
    const results: RangeVector[] = [];
    
    // Filter by query conditions
    const pods = query.includes('pod=') 
      ? [query.match(/pod="([^"]+)"/)?.[1] || MOCK_PODS[0]]
      : MOCK_PODS;
    const direction = query.includes('direction="') 
      ? query.match(/direction="([^"]+)"/)?.[1] 
      : undefined;
    const typeMatch = query.match(/type="([^"]+)"/);
    const type: string = typeMatch?.[1] ?? 'sim';

    pods.forEach(pod => {
      const directions = direction ? [direction] : [...DIRECTIONS];
      directions.forEach(dir => {
        let currentValue = type === 'sim' ? 1e6 + Math.random() * 2e6 : 1e5 + Math.random() * 2e5;
        const values: Array<[number, string]> = [];
        
        for (let i = 0; i < pointCount; i++) {
          const timestamp = start + i * stepSeconds;
          values.push([timestamp, currentValue.toFixed(2)]);
          currentValue = generateWalkValue(currentValue, 1e5, 0);
        }

        results.push({
          metric: { pod, direction: dir, type },
          values
        });
      });
    });

    return {
      status: 'success',
      data: { resultType: 'matrix', result: results }
    };
  }

  // Latency percentile query (histogram_quantile)
  if (query.includes('histogram_quantile') && query.includes('kuro_pod_latency_seconds_bucket')) {
    const results: RangeVector[] = [];
    
    // Extract quantile from query (e.g., 0.50, 0.95, 0.99)
    const quantileMatch = query.match(/histogram_quantile\((\d+\.?\d*)/);
    const quantile = quantileMatch ? parseFloat(quantileMatch[1]) : 0.95;
    
    // Base latency depends on quantile (higher quantile = higher latency)
    const baseLatency = 0.02 + (quantile * 0.05); // 20-70ms base
    
    // Check if aggregating by pod or single result
    const hasByPod = query.includes('by (pod');
    
    if (hasByPod) {
      // Return per-pod latency
      MOCK_PODS.forEach(pod => {
        let currentValue = baseLatency + Math.random() * 0.02;
        const values: Array<[number, string]> = [];
        
        for (let i = 0; i < pointCount; i++) {
          const timestamp = start + i * stepSeconds;
          values.push([timestamp, currentValue.toFixed(6)]);
          currentValue = generateWalkValue(currentValue, 0.01, 0.001);
        }
        
        results.push({
          metric: { pod },
          values
        });
      });
    } else {
      // Single aggregated result
      let currentValue = baseLatency + Math.random() * 0.02;
      const values: Array<[number, string]> = [];
      
      for (let i = 0; i < pointCount; i++) {
        const timestamp = start + i * stepSeconds;
        values.push([timestamp, currentValue.toFixed(6)]);
        currentValue = generateWalkValue(currentValue, 0.01, 0.001);
      }
      
      results.push({
        metric: {},
        values
      });
    }
    
    return {
      status: 'success',
      data: { resultType: 'matrix', result: results }
    };
  }

  // Latency histogram bucket query
  if (query.includes('kuro_pod_latency_seconds_bucket')) {
    const results: RangeVector[] = [];
    
    MOCK_PODS.forEach(pod => {
      LATENCY_BUCKETS.forEach(le => {
        let currentValue = le === '+Inf' ? 1000 : parseFloat(le) * 500 * (1 + Math.random());
        const values: Array<[number, string]> = [];
        
        for (let i = 0; i < pointCount; i++) {
          const timestamp = start + i * stepSeconds;
          values.push([timestamp, currentValue.toFixed(0)]);
          currentValue = generateWalkValue(currentValue, 50, 0);
        }

        results.push({
          metric: { pod, le },
          values
        });
      });
    });

    return {
      status: 'success',
      data: { resultType: 'matrix', result: results }
    };
  }
  
  // Latency sum/count query for average calculation
  if (query.includes('kuro_pod_latency_seconds_sum')) {
    const results: RangeVector[] = [];
    
    MOCK_PODS.forEach(pod => {
      let currentValue = 100 + Math.random() * 50;
      const values: Array<[number, string]> = [];
      
      for (let i = 0; i < pointCount; i++) {
        const timestamp = start + i * stepSeconds;
        values.push([timestamp, currentValue.toFixed(2)]);
        currentValue = generateWalkValue(currentValue, 10, 0);
      }
      
      results.push({
        metric: { pod },
        values
      });
    });
    
    return {
      status: 'success',
      data: { resultType: 'matrix', result: results }
    };
  }
  
  if (query.includes('kuro_pod_latency_seconds_count')) {
    const results: RangeVector[] = [];
    
    MOCK_PODS.forEach(pod => {
      let currentValue = 5000 + Math.random() * 1000;
      const values: Array<[number, string]> = [];
      
      for (let i = 0; i < pointCount; i++) {
        const timestamp = start + i * stepSeconds;
        values.push([timestamp, currentValue.toFixed(0)]);
        currentValue = generateWalkValue(currentValue, 100, 0);
      }
      
      results.push({
        metric: { pod },
        values
      });
    });
    
    return {
      status: 'success',
      data: { resultType: 'matrix', result: results }
    };
  }

  // Packet loss rate query
  if (query.includes('drop_packets') || query.includes('drop_bytes')) {
    const results: RangeVector[] = [];
    
    MOCK_PODS.forEach(pod => {
      let currentValue = Math.random() * 10;
      const values: Array<[number, string]> = [];
      
      for (let i = 0; i < pointCount; i++) {
        const timestamp = start + i * stepSeconds;
        values.push([timestamp, currentValue.toFixed(2)]);
        currentValue = generateWalkValue(currentValue, 2, 0);
      }

      results.push({
        metric: { pod },
        values
      });
    });

    return {
      status: 'success',
      data: { resultType: 'matrix', result: results }
    };
  }

  // Default empty result
  return {
    status: 'success',
    data: { resultType: 'matrix', result: [] }
  };
}

// ============================================================================
// Mock Label Values
// ============================================================================

/**
 * Mock get label values list
 * GET /api/v1/label/<label>/values
 */
export function mockLabelValues(label: string): PrometheusResponse<string[]> {
  switch (label) {
    case 'pod':
      return { status: 'success', data: MOCK_PODS };
    case 'direction':
      return { status: 'success', data: [...DIRECTIONS] };
    case 'type':
      return { status: 'success', data: [...TRAFFIC_TYPES] };
    case 'le':
      return { status: 'success', data: LATENCY_BUCKETS };
    default:
      return { status: 'success', data: [] };
  }
}

// ============================================================================
// Mock Metric Names
// ============================================================================

/**
 * Mock get all metric names
 * GET /api/v1/label/__name__/values
 */
export function mockMetricNames(): PrometheusResponse<string[]> {
  return {
    status: 'success',
    data: [
      'kuro_pod_traffic_bytes_total',
      'kuro_pod_traffic_packets_total',
      'kuro_pod_drop_bytes_total',
      'kuro_pod_drop_packets_total',
      'kuro_pod_latency_seconds_bucket',
      'kuro_pod_latency_seconds_count',
      'kuro_pod_latency_seconds_sum',
    ]
  };
}

// ============================================================================
// Export for convenience
// ============================================================================

export const prometheusMock = {
  instantQuery: mockInstantQuery,
  rangeQuery: mockRangeQuery,
  labelValues: mockLabelValues,
  metricNames: mockMetricNames,
  
  // Expose mock data for testing
  MOCK_PODS,
  DIRECTIONS,
  TRAFFIC_TYPES,
  LATENCY_BUCKETS,
};
