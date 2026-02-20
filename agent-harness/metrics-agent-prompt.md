# Metrics Agent Prompt - Kuro Frontend

You are the **Metrics Agent** for the Kuro frontend project. Your task is to implement the Metrics monitoring page based on the backend's Prometheus/Grafana integration.

## Core Understanding

### Backend Architecture

The Kuro backend has already implemented Prometheus metrics export:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Kuro Agent    │────▶│   Prometheus    │────▶│     Grafana     │
│  :8080/metrics  │     │    :9090        │     │     :3000       │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       │
        │ Prometheus format     │ PromQL queries        │ Dashboards
        ▼                       ▼                       ▼
   eBPF metrics          Time series storage       Visualization panels
```

### Prometheus Metrics (Backend Already Implemented)

Metrics exposed by the backend Agent (`internal/agent/opsapi/http_service.go`):

```promql
# Traffic statistics
kuro_pod_traffic_bytes_total{pod, direction, type}
kuro_pod_traffic_packets_total{pod, direction, type}

# Drop statistics
kuro_pod_drop_bytes_total{pod, direction, type}
kuro_pod_drop_packets_total{pod, direction, type}

# Latency histogram
kuro_pod_latency_seconds_bucket{pod, le}
kuro_pod_latency_seconds_count{pod}

# Labels:
# - pod: Pod name
# - direction: download/upload
# - type: sim/sys (simulation traffic/system traffic)
```

### Service Endpoints (deploy/quick-monitor.yaml)

| Service | Port | Purpose |
|---------|------|---------|
| Prometheus | NodePort 30091 | Time series data query |
| Grafana | NodePort 30092 | Dashboard visualization |
| Kuro Agent | 8080 | Direct metrics endpoint |

---

## ⚠️ Important Constraints

### Backend Constraints
- **Do not modify backend code**
- Backend has already implemented Prometheus metrics export
- Frontend queries data via Prometheus HTTP API
- Or embed Grafana iframe directly

### Mock Constraints
- Use mock data during development
- Mock data format must conform to Prometheus API specification
- Clearly mark places that require backend API

### Testing Constraints
- After completing each feature, must run `npm run build` to verify
- Build failure = Feature not complete

---

## Session Startup Flow

### Step 1: Confirm Working Directory
```bash
pwd  # Should be /home/alacrity/work/vibe/Kuro
```

### Step 2: Read Feature List
```bash
cat agent-harness/metrics-feature-list.json
```

### Step 3: Understand Backend Prometheus Integration
```bash
# View Agent metrics implementation
cat internal/agent/opsapi/http_service.go | grep -A 50 "handleMetrics"

# View Prometheus/Grafana deployment configuration
cat deploy/quick-monitor.yaml
```

### Step 4: Select Next Feature to Implement
Select the next pending feature from `metrics-feature-list.json` in development order.

---

## Development Order

### Phase 1: Infrastructure

| ID | Feature | Description |
|----|---------|-------------|
| METRICS-010 | Mock Prometheus Data | Simulate Prometheus API responses |
| METRICS-002 | Prometheus Query Service | HTTP API client |
| METRICS-007 | Time Range Selector | 5m/15m/1h/6h/24h |
| METRICS-008 | Auto Refresh Control | 5s/10s/30s/1m |

### Phase 2: Core Charts

| ID | Feature | PromQL Query |
|----|---------|--------------|
| METRICS-003 | Bandwidth Traffic Chart | `rate(kuro_pod_traffic_bytes_total[5m])` |
| METRICS-004 | Latency Distribution Chart | `histogram_quantile(0.95, ...)` |
| METRICS-005 | Packet Loss Rate Monitoring | `drop_packets / traffic_packets` |

### Phase 3: Page Integration

| ID | Feature |
|----|---------|
| METRICS-006 | Pod Selector |
| METRICS-009 | Metrics Page Layout |

### Phase 4: Grafana Integration (Requires Backend)

| ID | Feature |
|----|---------|
| METRICS-001 | Grafana iframe Integration |
| METRICS-011 | Grafana Dashboard Configuration Documentation |

---

## Prometheus API Client Implementation

### frontend/src/api/prometheus.ts

```typescript
/**
 * Prometheus HTTP API Client
 * Documentation: https://prometheus.io/docs/prometheus/latest/querying/api/
 */

const PROMETHEUS_URL = import.meta.env.VITE_PROMETHEUS_URL || 'http://localhost:30091';

interface PrometheusResponse<T> {
  status: 'success' | 'error';
  data: T;
  error?: string;
  errorType?: string;
}

interface InstantVector {
  metric: Record<string, string>;
  value: [number, string]; // [timestamp, value]
}

interface RangeVector {
  metric: Record<string, string>;
  values: Array<[number, string]>; // [[timestamp, value], ...]
}

export const prometheusClient = {
  /**
   * Instant Query
   * GET /api/v1/query?query=<query>
   */
  async instantQuery(query: string): Promise<InstantVector[]> {
    const response = await fetch(
      `${PROMETHEUS_URL}/api/v1/query?query=${encodeURIComponent(query)}`
    );
    const json: PrometheusResponse<{ resultType: string; result: InstantVector[] }> = 
      await response.json();
    
    if (json.status === 'error') {
      throw new Error(`Prometheus query error: ${json.error}`);
    }
    
    return json.data.result;
  },

  /**
   * Range Query
   * GET /api/v1/query_range?query=<query>&start=<start>&end=<end>&step=<step>
   */
  async rangeQuery(
    query: string,
    start: number,
    end: number,
    step: string = '15s'
  ): Promise<RangeVector[]> {
    const params = new URLSearchParams({
      query,
      start: start.toString(),
      end: end.toString(),
      step,
    });
    
    const response = await fetch(`${PROMETHEUS_URL}/api/v1/query_range?${params}`);
    const json: PrometheusResponse<{ resultType: string; result: RangeVector[] }> = 
      await response.json();
    
    if (json.status === 'error') {
      throw new Error(`Prometheus query error: ${json.error}`);
    }
    
    return json.data.result;
  },

  /**
   * Get Label Values
   * GET /api/v1/label/<label>/values
   */
  async getLabelValues(label: string): Promise<string[]> {
    const response = await fetch(`${PROMETHEUS_URL}/api/v1/label/${label}/values`);
    const json: PrometheusResponse<string[]> = await response.json();
    return json.data;
  },
};
```

---

## Common PromQL Queries

### Bandwidth Queries

```promql
# Download bandwidth per Pod (Mbps)
sum(rate(kuro_pod_traffic_bytes_total{direction="download", type="sim"}[5m])) by (pod) * 8 / 1e6

# Upload bandwidth per Pod (Mbps)
sum(rate(kuro_pod_traffic_bytes_total{direction="upload", type="sim"}[5m])) by (pod) * 8 / 1e6

# Total bandwidth trend
sum(rate(kuro_pod_traffic_bytes_total{type="sim"}[5m])) * 8 / 1e6
```

### Latency Queries

```promql
# P95 Latency
histogram_quantile(0.95, sum(rate(kuro_pod_latency_seconds_bucket[5m])) by (pod, le))

# P99 Latency
histogram_quantile(0.99, sum(rate(kuro_pod_latency_seconds_bucket[5m])) by (pod, le))

# Average Latency
rate(kuro_pod_latency_seconds_sum[5m]) / rate(kuro_pod_latency_seconds_count[5m])
```

### Packet Loss Rate Queries

```promql
# Packet loss rate per Pod (%)
sum(rate(kuro_pod_drop_packets_total[5m])) by (pod) 
  / sum(rate(kuro_pod_traffic_packets_total[5m])) by (pod) * 100
```

---

## Mock Data Format

### frontend/src/api/prometheusMock.ts

```typescript
/**
 * Mock Prometheus API Response
 * Format reference: https://prometheus.io/docs/prometheus/latest/querying/api/
 */

// Mock Pod name list
const MOCK_PODS = ['drone-0', 'drone-1', 'drone-2', 'ground-station-0', 'gateway-0'];

// Generate mock instant query response
export function mockInstantQuery(query: string): PrometheusResponse {
  const now = Date.now() / 1000;
  
  return {
    status: 'success',
    data: {
      resultType: 'vector',
      result: MOCK_PODS.map(pod => ({
        metric: { pod, direction: 'download', type: 'sim' },
        value: [now, (Math.random() * 1000000).toFixed(2)]
      }))
    }
  };
}

// Generate mock range query response
export function mockRangeQuery(
  query: string,
  start: number,
  end: number,
  step: string
): PrometheusResponse {
  const stepSeconds = parseDuration(step);
  const points = Math.floor((end - start) / stepSeconds);
  
  return {
    status: 'success',
    data: {
      resultType: 'matrix',
      result: MOCK_PODS.map(pod => {
        const values: Array<[number, string]> = [];
        let baseValue = Math.random() * 1000000;
        
        for (let i = 0; i < points; i++) {
          const timestamp = start + i * stepSeconds;
          const value = baseValue + (Math.random() - 0.5) * 100000;
          values.push([timestamp, Math.max(0, value).toFixed(2)]);
          baseValue = value;
        }
        
        return {
          metric: { pod, direction: 'download', type: 'sim' },
          values
        };
      })
    }
  };
}

// Get Mock Pod list
export function mockLabelValues(label: string): PrometheusResponse {
  if (label === 'pod') {
    return { status: 'success', data: MOCK_PODS };
  }
  return { status: 'success', data: [] };
}

function parseDuration(d: string): number {
  const match = d.match(/^(\d+)(s|m|h)$/);
  if (!match) return 15;
  const [, n, unit] = match;
  const multipliers: Record<string, number> = { s: 1, m: 60, h: 3600 };
  return parseInt(n) * multipliers[unit];
}
```

---

## Grafana iframe Integration

### frontend/src/components/metrics/GrafanaEmbed.tsx

```tsx
import { useState } from 'react';
import './GrafanaEmbed.css';

interface GrafanaEmbedProps {
  dashboardUid: string;
  panelId?: number;
  refresh?: string;
  theme?: 'dark' | 'light';
}

export function GrafanaEmbed({
  dashboardUid,
  panelId,
  refresh = '5s',
  theme = 'dark'
}: GrafanaEmbedProps) {
  const [isFullscreen, setIsFullscreen] = useState(false);
  
  // TODO: Need to configure VITE_GRAFANA_URL environment variable
  const grafanaUrl = import.meta.env.VITE_GRAFANA_URL || 'http://localhost:30092';
  
  // Build iframe URL
  // Reference: https://grafana.com/docs/grafana/latest/dashboards/create-dashboards/#embed-dashboard
  const embedPath = panelId
    ? `/d-solo/${dashboardUid}`  // Single panel
    : `/d/${dashboardUid}`;       // Entire dashboard
    
  const params = new URLSearchParams({
    orgId: '1',
    refresh,
    theme,
    ...(panelId && { panelId: panelId.toString() }),
    // Hide Grafana navigation bar
    kiosk: 'tv',
  });
  
  const iframeUrl = `${grafanaUrl}${embedPath}?${params}`;
  
  return (
    <div className={`grafana-embed ${isFullscreen ? 'fullscreen' : ''}`}>
      <div className="grafana-embed__toolbar">
        <span>Grafana Dashboard</span>
        <button onClick={() => setIsFullscreen(!isFullscreen)}>
          {isFullscreen ? 'Exit Fullscreen' : 'Fullscreen'}
        </button>
      </div>
      <iframe
        src={iframeUrl}
        width="100%"
        height="100%"
        frameBorder="0"
        title="Grafana Dashboard"
      />
    </div>
  );
}
```

---

## CSS Styles (Dark Theme)

```css
/* MetricsPage.css */

.metrics-page {
  background: #111217;
  min-height: 100vh;
  padding: 16px;
  color: #d4d4d4;
}

/* Toolbar */
.metrics-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  background: #1a1a2e;
  border-radius: 4px;
  margin-bottom: 16px;
}

/* Chart container */
.metrics-chart {
  background: #1a1a2e;
  border: 1px solid #2a2a3e;
  border-radius: 4px;
  padding: 16px;
  margin-bottom: 16px;
}

.metrics-chart__title {
  font-size: 14px;
  font-weight: 600;
  color: #fff;
  margin-bottom: 12px;
}

/* Grafana iframe */
.grafana-embed {
  background: #1a1a2e;
  border: 1px solid #2a2a3e;
  border-radius: 4px;
  overflow: hidden;
  height: 600px;
}

.grafana-embed.fullscreen {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  z-index: 1000;
  height: 100vh;
}
```

---

## Verification Checklist

After completing each feature:

```bash
# 1. Type check
cd frontend && npx tsc --noEmit

# 2. Run tests
npm run test:run

# 3. Build verification
npm run build

# 4. Start development server
npm run dev
# Visit http://localhost:5173/metrics
```

---

## Commit Convention

```bash
git commit -m "feat(metrics): [Feature Description] (METRICS-xxx)

- Implemented xxx component
- Added xxx Prometheus query
- Used mock data to support development

PromQL: rate(kuro_pod_traffic_bytes_total[5m])
TODO: Need to configure VITE_PROMETHEUS_URL environment variable
"
```

---

## Session End

Output session summary:

1. **Completed Features**: List IDs and names
2. **Build Verification Result**: Success/Failure
3. **Updated Files**: List all modified files
4. **Next Steps**: Next feature to implement
