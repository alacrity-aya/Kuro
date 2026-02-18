# Kuro Frontend System Design

**Version:** 1.0  
**Date:** 2026-02-18  
**Status:** Ready for Implementation

---

## 1. 现有后端 API 分析

### 已有 API (Controller HTTP Server :8080)

| 端点 | 方法 | 功能 | 前端可用性 |
|------|------|------|-----------|
| `/api/v1/topology` | GET | 获取拓扑节点列表 | ✅ 可用 |
| `/api/v1/agents` | GET | 获取已连接 Agent 列表 | ✅ 可用 |
| `/api/v1/policy/link` | POST | 应用链路策略 | ✅ 可用 |
| `/api/v1/policy/pod` | POST | 应用 Pod 策略 | ✅ 可用 |
| `/api/v1/policy/node` | POST | 应用节点策略 | ✅ 可用 |

### 已有数据模型

```
TopologyNode {
  name      string  // Pod name
  group     string  // Node group name  
  namespace string  // kuro-experiment
  ip        string  // Pod IP
  status    string  // Running, Pending, etc.
}
```

### 现有 API 的不足

| 缺失功能 | 前端需求影响 |
|---------|-------------|
| 无 NetworkTopology CRUD | 无法创建/删除拓扑 |
| 无 TrafficControl CRUD | 无法配置链路规则 |
| 无连接/边信息 | 无法绘制拓扑图连线 |
| 无 WebSocket 实时推送 | 无法实时更新状态 |
| Controller 无 metrics 端点 | 无法获取聚合监控数据 |

---

## 2. 前端需要的后端 API

### 2.1 拓扑管理 API

| 端点 | 方法 | 描述 | 优先级 |
|------|------|------|--------|
| `/api/v1/topologies` | GET | 列出所有 NetworkTopology | P0 |
| `/api/v1/topologies` | POST | 创建 NetworkTopology | P0 |
| `/api/v1/topologies/{name}` | GET | 获取单个拓扑详情 | P0 |
| `/api/v1/topologies/{name}` | DELETE | 删除拓扑 | P0 |
| `/api/v1/topologies/{name}/nodes` | GET | 获取拓扑下所有节点（已有） | P0 |
| `/api/v1/topologies/{name}/links` | GET | 获取拓扑下所有连接 | P1 |

**GET /api/v1/topologies/{name}/links 响应示例：**

```json
{
  "links": [
    {
      "id": "drone-ground-1",
      "source": "drone-follower-abc123",
      "sourceIP": "10.0.1.5",
      "target": "ground-station-xyz789", 
      "targetIP": "10.0.2.10",
      "bandwidth": "10Mbps",
      "latency": "50ms",
      "status": "active"
    }
  ]
}
```

### 2.2 流量控制 API

| 端点 | 方法 | 描述 | 优先级 |
|------|------|------|--------|
| `/api/v1/traffic-controls` | GET | 列出所有 TrafficControl | P0 |
| `/api/v1/traffic-controls` | POST | 创建 TrafficControl | P0 |
| `/api/v1/traffic-controls/{name}` | GET | 获取单个规则详情 | P0 |
| `/api/v1/traffic-controls/{name}` | PATCH | 更新流量规则 | P0 |
| `/api/v1/traffic-controls/{name}` | DELETE | 删除规则 | P0 |

**TrafficControl 请求/响应示例：**

```json
// POST /api/v1/traffic-controls
{
  "name": "weak-signal-area",
  "source": {
    "matchLabels": { "role": "follower", "team": "red" }
  },
  "destination": {
    "matchLabels": { "role": "ground-station" }
  },
  "policy": {
    "bandwidth": "5Mbps",
    "latency": "100ms",
    "jitter": "20ms",
    "packetLoss": "0.5%"
  }
}

// Response
{
  "name": "weak-signal-area",
  "phase": "Pending",
  "activeNodes": [],
  "message": "Rule created, waiting for sync"
}
```

### 2.3 实时监控 API

| 端点 | 方法 | 描述 | 优先级 |
|------|------|------|--------|
| `/api/v1/metrics/topology/{name}` | GET | 获取拓扑聚合指标 | P0 |
| `/api/v1/metrics/node/{podName}` | GET | 获取单节点指标 | P1 |
| `/ws/topology/{name}` | WebSocket | 实时拓扑状态推送 | P2 |

**GET /api/v1/metrics/topology/{name} 响应示例：**

```json
{
  "timestamp": "2026-02-18T10:30:00Z",
  "summary": {
    "totalNodes": 50,
    "runningNodes": 48,
    "totalBandwidthBps": 500000000,
    "avgLatencyNs": 50000000,
    "packetLossRate": 0.005
  },
  "nodes": [
    {
      "name": "drone-follower-abc123",
      "metrics": {
        "txBytes": 1024000,
        "rxBytes": 2048000,
        "txPackets": 1000,
        "rxPackets": 2000,
        "dropPackets": 5,
        "latencyNs": 45000000
      }
    }
  ]
}
```

### 2.4 WebSocket 实时推送

```
ws://controller:8080/ws/topology/{name}

// 服务端推送消息格式
{
  "type": "node_status",
  "data": {
    "nodeName": "drone-1",
    "status": "Running",
    "timestamp": "2026-02-18T10:30:00Z"
  }
}

{
  "type": "metrics_update",
  "data": {
    "nodeName": "drone-1",
    "txBytes": 1024000,
    "rxBytes": 2048000
  }
}
```

---

## 3. 后端改造需求

### 3.1 需要新增的代码

| 文件 | 改动 |
|------|------|
| `internal/controller/api/server.go` | 新增拓扑和流量控制的 CRUD handlers |
| `internal/controller/api/handlers_topology.go` | 新增拓扑管理 handlers（拆分文件） |
| `internal/controller/api/handlers_traffic.go` | 新增流量控制 handlers（拆分文件） |
| `internal/controller/api/handlers_metrics.go` | 新增指标聚合 handlers |
| `internal/controller/api/websocket.go` | 新增 WebSocket 支持 |
| `internal/domain/models.go` | 扩展响应结构体 |

### 3.2 Controller 需要新增的能力

1. **直接操作 CRD** - 现有代码通过 K8s client 已经支持
2. **聚合 Metrics** - 需要从 Agent 的 `/metrics` 端点拉取并聚合
3. **推导连接关系** - 根据 TrafficControl CRD + Pod Labels 推导拓扑图的边
4. **WebSocket Hub** - 管理客户端连接，广播实时事件

### 3.3 Metrics 数据流

```
Agent (:8080/metrics)  ──┐
Agent (:8080/metrics)  ──┼──> Controller (聚合) ──> Frontend
Agent (:8080/metrics)  ──┘           │
                                      │
VictoriaMetrics <─────────────────────┘
(Prometheus remote write)
```

---

## 4. 前端架构建议

### 4.1 技术栈建议

| 层级 | 技术 | 理由 |
|------|------|------|
| 框架 | React 18 | 生态成熟，TypeScript 支持好 |
| 构建工具 | Vite | 开发快，HMR 好 |
| 拓扑图 | React Flow | 轻量，支持拖拽，社区活跃 |
| 图表 | ECharts | 支持实时数据，图表类型丰富 |
| 状态管理 | Zustand | 轻量，TypeScript 友好 |
| HTTP 客户端 | TanStack Query | 自动缓存，后台刷新 |
| WebSocket |原生 WebSocket + React Hook | 简单场景无需复杂库 |

### 4.2 前端目录结构

```
frontend/
├── src/
│   ├── api/                 # API 客户端
│   │   ├── client.ts        # Axios 实例
│   │   ├── topology.ts      # 拓扑 API
│   │   ├── traffic.ts       # 流量控制 API
│   │   └── metrics.ts       # 监控 API
│   ├── components/
│   │   ├── topology/        # 拓扑图组件
│   │   │   ├── TopologyCanvas.tsx
│   │   │   ├── NodeCard.tsx
│   │   │   └── EdgeLabel.tsx
│   │   ├── metrics/         # 监控组件
│   │   │   ├── BandwidthChart.tsx
│   │   │   ├── LatencyChart.tsx
│   │   │   └── PacketLossGauge.tsx
│   │   └── common/          # 通用组件
│   ├── pages/
│   │   ├── Dashboard.tsx    # 仪表盘
│   │   ├── TopologyList.tsx # 拓扑列表
│   │   ├── TopologyDetail.tsx # 拓扑详情
│   │   └── TrafficControl.tsx # 流量控制
│   ├── hooks/
│   │   ├── useTopology.ts
│   │   ├── useMetrics.ts
│   │   └── useWebSocket.ts
│   ├── stores/
│   │   └── topologyStore.ts
│   └── types/
│       └── api.ts           # API 类型定义
├── package.json
├── vite.config.ts
└── tsconfig.json
```

### 4.3 关键组件设计

#### TopologyCanvas 组件

```tsx
interface TopologyCanvasProps {
  nodes: TopologyNode[];
  links: TopologyLink[];
  onNodeClick?: (node: TopologyNode) => void;
  onLinkClick?: (link: TopologyLink) => void;
}

// 使用 React Flow
function TopologyCanvas({ nodes, links, onNodeClick }: TopologyCanvasProps) {
  // 将业务数据转换为 React Flow 格式
  const flowNodes = nodes.map(n => ({
    id: n.name,
    data: { label: n.name, ...n },
    position: { x: 0, y: 0 }, // 自动布局
  }));
  
  const flowEdges = links.map(l => ({
    id: l.id,
    source: l.source,
    target: l.target,
    label: `${l.bandwidth} / ${l.latency}`,
  }));
  
  return <ReactFlow nodes={flowNodes} edges={flowEdges} />;
}
```

#### useWebSocket Hook

```tsx
function useTopologyWebSocket(topologyName: string) {
  const [status, setStatus] = useState<ConnectionStatus>('connecting');
  const [events, setEvents] = useState<TopologyEvent[]>([]);

  useEffect(() => {
    const ws = new WebSocket(`ws://${API_HOST}/ws/topology/${topologyName}`);
    
    ws.onopen = () => setStatus('connected');
    ws.onclose = () => setStatus('disconnected');
    ws.onmessage = (e) => {
      const event = JSON.parse(e.data);
      setEvents(prev => [...prev.slice(-100), event]);
    };
    
    return () => ws.close();
  }, [topologyName]);

  return { status, events };
}
```

---

## 5. API 实现优先级

### Phase 1 (MVP)

| API | 前端功能 | 后端改动量 |
|-----|---------|-----------|
| GET /api/v1/topologies | 拓扑列表页 | 小 - 直接 List CRD |
| GET /api/v1/topologies/{name}/nodes | 拓扑详情页节点 | 已有 |
| GET /api/v1/topologies/{name}/links | 拓扑详情页连线 | 中 - 需要推导逻辑 |
| GET /api/v1/traffic-controls | 流量规则列表 | 小 |
| PATCH /api/v1/traffic-controls/{name} | 调整参数滑块 | 小 - 已有类似逻辑 |

### Phase 2

| API | 前端功能 | 后端改动量 |
|-----|---------|-----------|
| POST /api/v1/topologies | 创建拓扑 | 中 - 需要验证 |
| GET /api/v1/metrics/topology/{name} | 监控面板 | 大 - 需要聚合 Agent metrics |

### Phase 3

| API | 前端功能 | 后端改动量 |
|-----|---------|-----------|
| /ws/topology/{name} | 实时更新 | 大 - WebSocket Hub |
| 低代码编辑器集成 | 代码注入 | 中 - 复用现有 CRD |

---

## 6. 后端最小改动清单

为了支持 V1 前端，后端需要新增以下代码：

### 6.1 新增 handler (internal/controller/api/)

```go
// handlers_topology.go
func (s *HTTPServer) handleListTopologies(w, r)    // GET /api/v1/topologies
func (s *HTTPServer) handleGetTopology(w, r)       // GET /api/v1/topologies/{name}
func (s *HTTPServer) handleCreateTopology(w, r)    // POST /api/v1/topologies
func (s *HTTPServer) handleDeleteTopology(w, r)    // DELETE /api/v1/topologies/{name}
func (s *HTTPServer) handleGetTopologyLinks(w, r)  // GET /api/v1/topologies/{name}/links

// handlers_traffic.go  
func (s *HTTPServer) handleListTrafficControls(w, r)
func (s *HTTPServer) handleGetTrafficControl(w, r)
func (s *HTTPServer) handleCreateTrafficControl(w, r)
func (s *HTTPServer) handleUpdateTrafficControl(w, r)
func (s *HTTPServer) handleDeleteTrafficControl(w, r)

// handlers_metrics.go
func (s *HTTPServer) handleGetTopologyMetrics(w, r) // GET /api/v1/metrics/topology/{name}
```

### 6.2 连接推导逻辑

```go
// 根据 TrafficControl CRD + Pod Labels 推导拓扑图的边
func (c *ControllerManager) DeriveLinks(topologyName string) ([]Link, error) {
    // 1. 获取该拓扑下所有 Pod
    // 2. 获取所有 TrafficControl 规则
    // 3. 对每个规则，匹配 Source/Destination Labels
    // 4. 生成所有 (srcPod, dstPod) 连接对
}
```

---

## 7. 数据契约

### 前端需要的完整类型定义

```typescript
// types/api.ts

// 拓扑节点
interface TopologyNode {
  name: string;
  group: string;
  namespace: string;
  ip: string;
  status: 'Running' | 'Pending' | 'Failed' | 'Unknown';
}

// 拓扑连接
interface TopologyLink {
  id: string;
  source: string;      // Pod name
  sourceIP: string;
  target: string;      // Pod name
  targetIP: string;
  bandwidth: string;   // "10Mbps"
  latency: string;     // "50ms"
  jitter?: string;     // "10ms"
  packetLoss?: string; // "0.5%"
  status: 'active' | 'pending' | 'failed';
}

// NetworkTopology CRD
interface NetworkTopology {
  name: string;
  namespace: string;
  spec: {
    nodeGroups: NodeGroup[];
  };
  status: {
    readyNodes: number;
  };
}

interface NodeGroup {
  name: string;
  replicas: number;
  image: string;
  labels?: Record<string, string>;
}

// TrafficControl CRD
interface TrafficControl {
  name: string;
  namespace: string;
  spec: {
    priority: number;
    source: LabelSelector;
    destination: LabelSelector;
    policy: LinkPolicySpec;
  };
  status: {
    phase: 'Pending' | 'Active' | 'PartialFail' | 'Failed';
    activeNodes: string[];
    message: string;
  };
}

interface LabelSelector {
  matchLabels: Record<string, string>;
}

interface LinkPolicySpec {
  bandwidth?: string;
  latency?: string;
  jitter?: string;
  packetLoss?: string;
}

// 监控指标
interface TopologyMetrics {
  timestamp: string;
  summary: {
    totalNodes: number;
    runningNodes: number;
    totalBandwidthBps: number;
    avgLatencyNs: number;
    packetLossRate: number;
  };
  nodes: NodeMetrics[];
}

interface NodeMetrics {
  name: string;
  metrics: {
    txBytes: number;
    rxBytes: number;
    txPackets: number;
    rxPackets: number;
    dropPackets: number;
    latencyNs: number;
  };
}
```

---

## 8. 下一步行动

1. **后端**：实现 Phase 1 API（拓扑列表、连接推导、流量控制 CRUD）
2. **前端**：初始化 React 项目，实现拓扑列表页
3. **联调**：使用 Mock 数据验证前端组件，逐步接入真实 API
