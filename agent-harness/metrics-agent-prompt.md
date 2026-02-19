# Metrics Agent Prompt - Kuro Frontend

你是 Kuro 前端项目的 **Metrics Agent**。你的任务是基于后端的 Prometheus/Grafana 集成，实现 Metrics 监控页面。

## 核心理解

### 后端架构

Kuro 后端已经实现了 Prometheus metrics 导出：

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Kuro Agent    │────▶│   Prometheus    │────▶│     Grafana     │
│  :8080/metrics  │     │    :9090        │     │     :3000       │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       │
        │ Prometheus format     │ PromQL queries        │ Dashboards
        ▼                       ▼                       ▼
   eBPF metrics          时序数据存储            可视化面板
```

### Prometheus Metrics (后端已实现)

后端 Agent 暴露的 metrics (`internal/agent/opsapi/http_service.go`):

```promql
# 流量统计
kuro_pod_traffic_bytes_total{pod, direction, type}
kuro_pod_traffic_packets_total{pod, direction, type}

# 丢包统计
kuro_pod_drop_bytes_total{pod, direction, type}
kuro_pod_drop_packets_total{pod, direction, type}

# 延迟直方图
kuro_pod_latency_seconds_bucket{pod, le}
kuro_pod_latency_seconds_count{pod}

# Labels:
# - pod: Pod 名称
# - direction: download/upload
# - type: sim/sys (模拟流量/系统流量)
```

### 服务端点 (deploy/quick-monitor.yaml)

| 服务 | 端口 | 用途 |
|------|------|------|
| Prometheus | NodePort 30091 | 时序数据查询 |
| Grafana | NodePort 30092 | 仪表板可视化 |
| Kuro Agent | 8080 | 直接 metrics 端点 |

---

## ⚠️ 重要约束

### 后端约束
- **不修改后端代码**
- 后端已实现 Prometheus metrics 导出
- 前端通过 Prometheus HTTP API 查询数据
- 或直接嵌入 Grafana iframe

### Mock 约束
- 开发时使用 mock 数据
- Mock 数据格式需符合 Prometheus API 规范
- 明确标注需要后端 API 的地方

### 测试约束
- 每完成一个功能，必须运行 `npm run build` 验证
- 构建失败 = 功能未完成

---

## Session 启动流程

### Step 1: 确认工作目录
```bash
pwd  # 应该是 /home/alacrity/work/vibe/Kuro
```

### Step 2: 阅读功能列表
```bash
cat agent-harness/metrics-feature-list.json
```

### Step 3: 理解后端 Prometheus 集成
```bash
# 查看 Agent metrics 实现
cat internal/agent/opsapi/http_service.go | grep -A 50 "handleMetrics"

# 查看 Prometheus/Grafana 部署配置
cat deploy/quick-monitor.yaml
```

### Step 4: 选择下一个待实现功能
从 `metrics-feature-list.json` 中按开发顺序选择功能。

---

## 开发顺序

### Phase 1: 基础设施

| ID | 功能 | 说明 |
|----|------|------|
| METRICS-010 | Mock Prometheus 数据 | 模拟 Prometheus API 响应 |
| METRICS-002 | Prometheus 查询服务 | HTTP API 客户端 |
| METRICS-007 | 时间范围选择器 | 5m/15m/1h/6h/24h |
| METRICS-008 | 自动刷新控制 | 5s/10s/30s/1m |

### Phase 2: 核心图表

| ID | 功能 | PromQL 查询 |
|----|------|-------------|
| METRICS-003 | 带宽流量图表 | `rate(kuro_pod_traffic_bytes_total[5m])` |
| METRICS-004 | 延迟分布图表 | `histogram_quantile(0.95, ...)` |
| METRICS-005 | 丢包率监控 | `drop_packets / traffic_packets` |

### Phase 3: 页面集成

| ID | 功能 |
|----|------|
| METRICS-006 | Pod 选择器 |
| METRICS-009 | Metrics 页面布局 |

### Phase 4: Grafana 集成 (需要后端)

| ID | 功能 |
|----|------|
| METRICS-001 | Grafana iframe 集成 |
| METRICS-011 | Grafana Dashboard 配置文档 |

---

## Prometheus API 客户端实现

### frontend/src/api/prometheus.ts

```typescript
/**
 * Prometheus HTTP API 客户端
 * 文档: https://prometheus.io/docs/prometheus/latest/querying/api/
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
   * 即时查询
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
   * 范围查询
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
   * 获取标签值列表
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

## 常用 PromQL 查询

### 带宽查询

```promql
# 各 Pod 下载带宽 (Mbps)
sum(rate(kuro_pod_traffic_bytes_total{direction="download", type="sim"}[5m])) by (pod) * 8 / 1e6

# 各 Pod 上传带宽 (Mbps)
sum(rate(kuro_pod_traffic_bytes_total{direction="upload", type="sim"}[5m])) by (pod) * 8 / 1e6

# 总带宽趋势
sum(rate(kuro_pod_traffic_bytes_total{type="sim"}[5m])) * 8 / 1e6
```

### 延迟查询

```promql
# P95 延迟
histogram_quantile(0.95, sum(rate(kuro_pod_latency_seconds_bucket[5m])) by (pod, le))

# P99 延迟
histogram_quantile(0.99, sum(rate(kuro_pod_latency_seconds_bucket[5m])) by (pod, le))

# 平均延迟
rate(kuro_pod_latency_seconds_sum[5m]) / rate(kuro_pod_latency_seconds_count[5m])
```

### 丢包率查询

```promql
# 各 Pod 丢包率 (%)
sum(rate(kuro_pod_drop_packets_total[5m])) by (pod) 
  / sum(rate(kuro_pod_traffic_packets_total[5m])) by (pod) * 100
```

---

## Mock 数据格式

### frontend/src/api/prometheusMock.ts

```typescript
/**
 * Mock Prometheus API 响应
 * 格式参考: https://prometheus.io/docs/prometheus/latest/querying/api/
 */

// Mock Pod 名称列表
const MOCK_PODS = ['drone-0', 'drone-1', 'drone-2', 'ground-station-0', 'gateway-0'];

// 生成模拟的即时查询响应
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

// 生成模拟的范围查询响应
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

// 获取 Mock Pod 列表
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

## Grafana iframe 集成

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
  
  // TODO: 需要配置 VITE_GRAFANA_URL 环境变量
  const grafanaUrl = import.meta.env.VITE_GRAFANA_URL || 'http://localhost:30092';
  
  // 构建 iframe URL
  // 参考: https://grafana.com/docs/grafana/latest/dashboards/create-dashboards/#embed-dashboard
  const embedPath = panelId
    ? `/d-solo/${dashboardUid}`  // 单个面板
    : `/d/${dashboardUid}`;       // 整个仪表板
    
  const params = new URLSearchParams({
    orgId: '1',
    refresh,
    theme,
    ...(panelId && { panelId: panelId.toString() }),
    // 隐藏 Grafana 导航栏
    kiosk: 'tv',
  });
  
  const iframeUrl = `${grafanaUrl}${embedPath}?${params}`;
  
  return (
    <div className={`grafana-embed ${isFullscreen ? 'fullscreen' : ''}`}>
      <div className="grafana-embed__toolbar">
        <span>Grafana Dashboard</span>
        <button onClick={() => setIsFullscreen(!isFullscreen)}>
          {isFullscreen ? '退出全屏' : '全屏'}
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

## CSS 样式 (深色主题)

```css
/* MetricsPage.css */

.metrics-page {
  background: #111217;
  min-height: 100vh;
  padding: 16px;
  color: #d4d4d4;
}

/* 工具栏 */
.metrics-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  background: #1a1a2e;
  border-radius: 4px;
  margin-bottom: 16px;
}

/* 图表容器 */
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

## 验证清单

每个功能完成后：

```bash
# 1. 类型检查
cd frontend && npx tsc --noEmit

# 2. 运行测试
npm run test:run

# 3. 构建验证
npm run build

# 4. 启动开发服务器
npm run dev
# 访问 http://localhost:5173/metrics
```

---

## 提交规范

```bash
git commit -m "feat(metrics): [功能描述] (METRICS-xxx)

- 实现了 xxx 组件
- 添加了 xxx Prometheus 查询
- 使用 mock 数据支持开发

PromQL: rate(kuro_pod_traffic_bytes_total[5m])
TODO: 需要配置 VITE_PROMETHEUS_URL 环境变量
"
```

---

## 会话结束

输出会话摘要：

1. **完成的功能**: 列出 ID 和名称
2. **构建验证结果**: 成功/失败
3. **更新的文件**: 列出所有修改的文件
4. **下一步建议**: 下一个要实现的功能