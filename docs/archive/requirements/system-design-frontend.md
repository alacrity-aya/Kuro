# Kuro Frontend System Design

**Version:** 1.0  
**Date:** 2026-02-18  
**Status:** Ready for Implementation

---

## 1. Existing Backend API Analysis

### Existing APIs (Controller HTTP Server :8080)

| Endpoint | Method | Function | Frontend Availability |
|----------|--------|----------|----------------------|
| `/api/v1/topology` | GET | Get topology node list | ✅ Available |
| `/api/v1/agents` | GET | Get connected Agent list | ✅ Available |
| `/api/v1/policy/link` | POST | Apply link policy | ✅ Available |
| `/api/v1/policy/pod` | POST | Apply Pod policy | ✅ Available |
| `/api/v1/policy/node` | POST | Apply node policy | ✅ Available |

### Existing Data Models

```
TopologyNode {
  name      string  // Pod name
  group     string  // Node group name  
  namespace string  // kuro-experiment
  ip        string  // Pod IP
  status    string  // Running, Pending, etc.
}
```

### Limitations of Existing APIs

| Missing Feature | Frontend Impact |
|-----------------|-----------------|
| No NetworkTopology CRUD | Cannot create/delete topologies |
| No TrafficControl CRUD | Cannot configure link rules |
| No connection/edge information | Cannot draw topology graph connections |
| No WebSocket real-time push | Cannot update status in real-time |
| Controller has no metrics endpoint | Cannot get aggregated monitoring data |

---

## 2. Backend APIs Needed by Frontend

### 2.1 Topology Management API

| Endpoint | Method | Description | Priority |
|----------|--------|-------------|----------|
| `/api/v1/topologies` | GET | List all NetworkTopologies | P0 |
| `/api/v1/topologies` | POST | Create NetworkTopology | P0 |
| `/api/v1/topologies/{name}` | GET | Get single topology details | P0 |
| `/api/v1/topologies/{name}` | DELETE | Delete topology | P0 |
| `/api/v1/topologies/{name}/nodes` | GET | Get all nodes under topology (existing) | P0 |
| `/api/v1/topologies/{name}/links` | GET | Get all connections under topology | P1 |

**GET /api/v1/topologies/{name}/links Response Example:**

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

### 2.2 Traffic Control API

| Endpoint | Method | Description | Priority |
|----------|--------|-------------|----------|
| `/api/v1/traffic-controls` | GET | List all TrafficControls | P0 |
| `/api/v1/traffic-controls` | POST | Create TrafficControl | P0 |
| `/api/v1/traffic-controls/{name}` | GET | Get single rule details | P0 |
| `/api/v1/traffic-controls/{name}` | PATCH | Update traffic rule | P0 |
| `/api/v1/traffic-controls/{name}` | DELETE | Delete rule | P0 |

**TrafficControl Request/Response Example:**

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

### 2.3 Real-time Monitoring API

| Endpoint | Method | Description | Priority |
|----------|--------|-------------|----------|
| `/api/v1/metrics/topology/{name}` | GET | Get topology aggregated metrics | P0 |
| `/api/v1/metrics/node/{podName}` | GET | Get single node metrics | P1 |
| `/ws/topology/{name}` | WebSocket | Real-time topology status push | P2 |

**GET /api/v1/metrics/topology/{name} Response Example:**

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

### 2.4 WebSocket Real-time Push

```
ws://controller:8080/ws/topology/{name}

// Server push message format
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

## 3. Backend Modification Requirements

### 3.1 Code to Add

| File | Change |
|------|--------|
| `internal/controller/api/server.go` | Add topology and traffic control CRUD handlers |
| `internal/controller/api/handlers_topology.go` | Add topology management handlers (split file) |
| `internal/controller/api/handlers_traffic.go` | Add traffic control handlers (split file) |
| `internal/controller/api/handlers_metrics.go` | Add metrics aggregation handlers |
| `internal/controller/api/websocket.go` | Add WebSocket support |
| `internal/domain/models.go` | Extend response structures |

### 3.2 Capabilities Controller Needs to Add

1. **Direct CRD Operations** - Existing code already supports via K8s client
2. **Aggregated Metrics** - Need to pull and aggregate from Agent's `/metrics` endpoint
3. **Derive Connections** - Derive topology graph edges based on TrafficControl CRD + Pod Labels
4. **WebSocket Hub** - Manage client connections, broadcast real-time events

### 3.3 Metrics Data Flow

```
Agent (:8080/metrics)  ──┐
Agent (:8080/metrics)  ──┼──> Controller (aggregate) ──> Frontend
Agent (:8080/metrics)  ──┘           │
                                      │
VictoriaMetrics <─────────────────────┘
(Prometheus remote write)
```

---

## 4. Frontend Architecture Recommendations

### 4.1 Technology Stack Recommendations

| Layer | Technology | Reason |
|-------|------------|--------|
| Framework | React 18 | Mature ecosystem, good TypeScript support |
| Build Tool | Vite | Fast development, good HMR |
| Topology Graph | React Flow | Lightweight, supports drag-drop, active community |
| Charts | ECharts | Supports real-time data, rich chart types |
| State Management | Zustand | Lightweight, TypeScript friendly |
| HTTP Client | TanStack Query | Auto caching, background refresh |
| WebSocket | Native WebSocket + React Hook | Simple scenarios don't need complex libraries |

### 4.2 Frontend Directory Structure

```
frontend/
├── src/
│   ├── api/                 # API client
│   │   ├── client.ts        # Axios instance
│   │   ├── topology.ts      # Topology API
│   │   ├── traffic.ts       # Traffic control API
│   │   └── metrics.ts       # Monitoring API
│   ├── components/
│   │   ├── topology/        # Topology graph components
│   │   │   ├── TopologyCanvas.tsx
│   │   │   ├── NodeCard.tsx
│   │   │   └── EdgeLabel.tsx
│   │   ├── metrics/         # Monitoring components
│   │   │   ├── BandwidthChart.tsx
│   │   │   ├── LatencyChart.tsx
│   │   │   └── PacketLossGauge.tsx
│   │   └── common/          # Common components
│   ├── pages/
│   │   ├── Dashboard.tsx    # Dashboard
│   │   ├── TopologyList.tsx # Topology list
│   │   ├── TopologyDetail.tsx # Topology details
│   │   └── TrafficControl.tsx # Traffic control
│   ├── hooks/
│   │   ├── useTopology.ts
│   │   ├── useMetrics.ts
│   │   └── useWebSocket.ts
│   ├── stores/
│   │   └── topologyStore.ts
│   └── types/
│       └── api.ts           # API type definitions
├── package.json
├── vite.config.ts
└── tsconfig.json
```

### 4.3 Key Component Design

#### TopologyCanvas Component

```tsx
interface TopologyCanvasProps {
  nodes: TopologyNode[];
  links: TopologyLink[];
  onNodeClick?: (node: TopologyNode) => void;
  onLinkClick?: (link: TopologyLink) => void;
}

// Using React Flow
function TopologyCanvas({ nodes, links, onNodeClick }: TopologyCanvasProps) {
  // Convert business data to React Flow format
  const flowNodes = nodes.map(n => ({
    id: n.name,
    data: { label: n.name, ...n },
    position: { x: 0, y: 0 }, // Auto layout
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

## 5. API Implementation Priority

### Phase 1 (MVP)

| API | Frontend Feature | Backend Effort |
|-----|------------------|----------------|
| GET /api/v1/topologies | Topology list page | Small - Direct List CRD |
| GET /api/v1/topologies/{name}/nodes | Topology detail page nodes | Already exists |
| GET /api/v1/topologies/{name}/links | Topology detail page connections | Medium - Needs derivation logic |
| GET /api/v1/traffic-controls | Traffic rules list | Small |
| PATCH /api/v1/traffic-controls/{name} | Adjust parameter sliders | Small - Similar logic exists |

### Phase 2

| API | Frontend Feature | Backend Effort |
|-----|------------------|----------------|
| POST /api/v1/topologies | Create topology | Medium - Needs validation |
| GET /api/v1/metrics/topology/{name} | Monitoring dashboard | Large - Needs Agent metrics aggregation |

### Phase 3

| API | Frontend Feature | Backend Effort |
|-----|------------------|----------------|
| /ws/topology/{name} | Real-time updates | Large - WebSocket Hub |
| Low-code editor integration | Code injection | Medium - Reuse existing CRD |

---

## 6. Backend Minimal Change List

To support V1 frontend, backend needs to add the following code:

### 6.1 New Handlers (internal/controller/api/)

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

### 6.2 Connection Derivation Logic

```go
// Derive topology graph edges based on TrafficControl CRD + Pod Labels
func (c *ControllerManager) DeriveLinks(topologyName string) ([]Link, error) {
    // 1. Get all Pods under this topology
    // 2. Get all TrafficControl rules
    // 3. For each rule, match Source/Destination Labels
    // 4. Generate all (srcPod, dstPod) connection pairs
}
```

---

## 7. Data Contract

### Complete Type Definitions Needed by Frontend

```typescript
// types/api.ts

// Topology node
interface TopologyNode {
  name: string;
  group: string;
  namespace: string;
  ip: string;
  status: 'Running' | 'Pending' | 'Failed' | 'Unknown';
}

// Topology connection
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

// Monitoring metrics
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

## 8. Next Steps

1. **Backend**: Implement Phase 1 APIs (topology list, connection derivation, traffic control CRUD)
2. **Frontend**: Initialize React project, implement topology list page
3. **Integration Testing**: Use mock data to verify frontend components, gradually integrate real APIs