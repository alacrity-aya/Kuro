# Frontend-Backend API Integration Document

This document records all backend API endpoints required by the frontend, for guiding backend development implementation.

## Overview

The frontend currently uses Mock API for development. Two types of APIs need to be implemented:

1. **Kuro API** - Custom Kubernetes CRD operation API
2. **Prometheus API** - Monitoring metrics query API

---

## 1. Kuro API

### Basic Information

- **Base URL**: `/api/v1`
- **Authentication**: Kubernetes ServiceAccount or Token
- **Response Format**: JSON

### Common Response Structure

```typescript
interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

interface ListResult<T> {
  items: T[];
  totalCount: number;
  continueToken?: string;  // Pagination token (optional)
}
```

---

### 1.1 NetworkTopology API

#### 1.1.1 List Query

```
GET /api/v1/namespaces/{namespace}/networktopologies
```

**Path Parameters**:
| Parameter | Type | Required | Description |
|------|------|------|------|
| namespace | string | Yes | Namespace |

**Query Parameters**:
| Parameter | Type | Required | Description |
|------|------|------|------|
| limit | int | No | Items per page |
| continue | string | No | Pagination token |
| labelSelector | string | No | Label selector |

**Response**: `ApiResponse<ListResult<NetworkTopology>>`

---

#### 1.1.2 Detail Query

```
GET /api/v1/namespaces/{namespace}/networktopologies/{name}
```

**Path Parameters**:
| Parameter | Type | Required | Description |
|------|------|------|------|
| namespace | string | Yes | Namespace |
| name | string | Yes | Resource name |

**Response**: `ApiResponse<NetworkTopology>`

---

#### 1.1.3 Create

```
POST /api/v1/namespaces/{namespace}/networktopologies
```

**Request Body**: `NetworkTopology` (without status)

**Response**: `ApiResponse<NetworkTopology>`

---

#### 1.1.4 Delete

```
DELETE /api/v1/namespaces/{namespace}/networktopologies/{name}
```

**Path Parameters**:
| Parameter | Type | Required | Description |
|------|------|------|------|
| namespace | string | Yes | Namespace |
| name | string | Yes | Resource name |

**Response**: `ApiResponse<void>`

---

### 1.2 TrafficControl API

#### 1.2.1 List Query

```
GET /api/v1/namespaces/{namespace}/trafficcontrols
```

**Path Parameters**:
| Parameter | Type | Required | Description |
|------|------|------|------|
| namespace | string | Yes | Namespace |

**Query Parameters**:
| Parameter | Type | Required | Description |
|------|------|------|------|
| limit | int | No | Items per page |
| continue | string | No | Pagination token |
| labelSelector | string | No | Label selector |

**Response**: `ApiResponse<ListResult<TrafficControl>>`

---

#### 1.2.2 Detail Query

```
GET /api/v1/namespaces/{namespace}/trafficcontrols/{name}
```

**Response**: `ApiResponse<TrafficControl>`

---

#### 1.2.3 Create

```
POST /api/v1/namespaces/{namespace}/trafficcontrols
```

**Request Body**: `TrafficControl` (without status)

**Response**: `ApiResponse<TrafficControl>`

---

#### 1.2.4 Update

```
PUT /api/v1/namespaces/{namespace}/trafficcontrols/{name}
```

**Request Body**: `TrafficControl` (complete object)

**Response**: `ApiResponse<TrafficControl>`

---

#### 1.2.5 Delete

```
DELETE /api/v1/namespaces/{namespace}/trafficcontrols/{name}
```

**Response**: `ApiResponse<void>`

---

### 1.3 Topology Visualization API

#### 1.3.1 Get Topology Nodes

```
GET /api/v1/namespaces/{namespace}/topologies/{name}/nodes
```

**Path Parameters**:
| Parameter | Type | Required | Description |
|------|------|------|------|
| namespace | string | Yes | Namespace |
| name | string | Yes | Topology name |

**Response**: `ApiResponse<TopologyNode[]>`

**Return Data Structure**:
```typescript
interface TopologyNode {
  id: string;                    // Pod UID
  name: string;                  // Pod name
  role: NodeRole;                // Node role
  ip: string;                    // Pod IP
  labels: Record<string, string>;
  status: 'running' | 'pending' | 'failed' | 'unknown';
  groupId: string;               // NodeGroup name
  x?: number;                    // Visualization coordinates (optional)
  y?: number;
}

type NodeRole = 'drone' | 'ground-station' | 'gateway' | 'server' | 'client' | 'custom';
```

---

#### 1.3.2 Get Topology Links

```
GET /api/v1/namespaces/{namespace}/topologies/{name}/links
```

**Response**: `ApiResponse<TopologyLink[]>`

**Return Data Structure**:
```typescript
interface TopologyLink {
  id: string;                    // Link unique identifier
  sourceId: string;              // Source node ID
  targetId: string;              // Target node ID
  policy?: TrafficPolicy;        // Applied traffic policy
  status: 'active' | 'inactive' | 'pending';
  metrics?: LinkMetrics;         // Current metrics
}

interface TrafficPolicy {
  bandwidth: string;    // e.g., "10Mbps"
  latency: string;      // e.g., "50ms"
  jitter: string;       // e.g., "10ms"
  packetLoss: string;   // e.g., "0.5%"
}

interface LinkMetrics {
  bandwidthUsage: number;    // Percentage (0-100)
  currentLatency: number;    // ms
  currentJitter: number;     // ms
  packetLossRate: number;    // Percentage (0-100)
  bytesPerSecond: number;
  packetsPerSecond: number;
}
```

---

### 1.4 Metrics API (Optional Implementation)

#### 1.4.1 Node Metrics History

```
GET /api/v1/nodes/{nodeId}/metrics
```

**Query Parameters**:
| Parameter | Type | Required | Description |
|------|------|------|------|
| start | int | No | Start timestamp (Unix) |
| end | int | No | End timestamp (Unix) |
| step | string | No | Step size (e.g., "15s") |

**Response**: `ApiResponse<NodeMetrics>`

```typescript
interface NodeMetrics {
  nodeId: string;
  cpuUsage: TimeSeriesPoint[];
  memoryUsage: TimeSeriesPoint[];
  networkIn: TimeSeriesPoint[];
  networkOut: TimeSeriesPoint[];
}

interface TimeSeriesPoint {
  timestamp: number;
  value: number;
}
```

---

#### 1.4.2 Link Metrics History

```
GET /api/v1/links/{linkId}/metrics
```

**Response**: `ApiResponse<LinkMetricsHistory>`

```typescript
interface LinkMetricsHistory {
  linkId: string;
  bandwidth: TimeSeriesPoint[];
  latency: TimeSeriesPoint[];
  packetLoss: TimeSeriesPoint[];
}
```

---

## 2. Prometheus API

### Basic Information

- **Service Address**: Prometheus NodePort (default `:30091`)
- **Authentication**: None (or based on cluster configuration)

### Supported Endpoints

#### 2.1 Instant Query

```
GET /api/v1/query
```

**Query Parameters**:
| Parameter | Type | Required | Description |
|------|------|------|------|
| query | string | Yes | PromQL query expression |
| time | int | No | Query timestamp (Unix timestamp) |
| timeout | int | No | Timeout (seconds) |

**Response**:
```json
{
  "status": "success",
  "data": {
    "resultType": "vector",
    "result": [
      {
        "metric": {"__name__": "kuro_pod_traffic_bytes_total", "pod": "drone-0"},
        "value": [1708700000, "1234567"]
      }
    ]
  }
}
```

---

#### 2.2 Range Query

```
GET /api/v1/query_range
```

**Query Parameters**:
| Parameter | Type | Required | Description |
|------|------|------|------|
| query | string | Yes | PromQL query expression |
| start | int | Yes | Start timestamp |
| end | int | Yes | End timestamp |
| step | string | Yes | Step size (e.g., "15s") |
| timeout | int | No | Timeout (seconds) |

**Response**:
```json
{
  "status": "success",
  "data": {
    "resultType": "matrix",
    "result": [
      {
        "metric": {"__name__": "kuro_pod_traffic_bytes_total", "pod": "drone-0"},
        "values": [[1708700000, "1234567"], [1708700015, "1245678"]]
      }
    ]
  }
}
```

---

#### 2.3 Label Values Query

```
GET /api/v1/label/{label}/values
```

**Example**: `/api/v1/label/pod/values`

**Response**:
```json
{
  "status": "success",
  "data": ["drone-0", "drone-1", "ground-station-0"]
}
```

---

### Predefined PromQL Queries

PromQL query templates used by the frontend:

```promql
# Pod traffic bytes
kuro_pod_traffic_bytes_total{pod="<pod>", direction="<direction>", traffic_type="<type>"}

# Pod traffic packets
kuro_pod_traffic_packets_total{pod="<pod>", direction="<direction>", traffic_type="<type>"}

# Pod dropped bytes
kuro_pod_drop_bytes_total{pod="<pod>", direction="<direction>", traffic_type="<type>"}

# Pod dropped packets
kuro_pod_drop_packets_total{pod="<pod>", direction="<direction>", traffic_type="<type>"}

# Latency histogram
kuro_pod_latency_seconds_bucket{pod="<pod>", direction="<direction>", traffic_type="<type>"}
kuro_pod_latency_seconds_count{pod="<pod>", direction="<direction>", traffic_type="<type>"}
kuro_pod_latency_seconds_sum{pod="<pod>", direction="<direction>", traffic_type="<type>"}

# Calculate average latency (last 5 minutes)
rate(kuro_pod_latency_seconds_sum[5m]) / rate(kuro_pod_latency_seconds_count[5m])

# Calculate P99 latency
histogram_quantile(0.99, rate(kuro_pod_latency_seconds_bucket[5m]))
```

**Variable Description**:
- `<pod>`: Pod name (e.g., "drone-0")
- `<direction>`: Direction ("download" | "upload")
- `<traffic_type>`: Traffic type ("sim" | "sys")

---

## 3. Data Type Definitions

### 3.1 NetworkTopology CRD

```typescript
interface NetworkTopology {
  apiVersion: 'simulation.kuro.io/v1alpha1';
  kind: 'NetworkTopology';
  metadata: ObjectMeta;
  spec: NetworkTopologySpec;
  status?: NetworkTopologyStatus;
}

interface ObjectMeta {
  name: string;
  namespace: string;
  uid: string;
  creationTimestamp: string;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
}

interface NetworkTopologySpec {
  nodeGroups: NodeGroup[];
}

interface NodeGroup {
  name: string;
  replicas: number;
  image: string;
  labels?: Record<string, string>;
  resources?: {
    cpu?: string;
    memory?: string;
  };
}

interface NetworkTopologyStatus {
  phase: 'Pending' | 'Running' | 'Succeeded' | 'Failed' | 'Unknown';
  nodeCount: number;
  readyNodes: number;
  conditions?: {
    type: string;
    status: 'True' | 'False' | 'Unknown';
    message?: string;
    lastTransitionTime?: string;
  }[];
}
```

### 3.2 TrafficControl CRD

```typescript
interface TrafficControl {
  apiVersion: 'simulation.kuro.io/v1alpha1';
  kind: 'TrafficControl';
  metadata: ObjectMeta;
  spec: TrafficControlSpec;
  status?: TrafficControlStatus;
}

interface TrafficControlSpec {
  source: LabelSelector;
  destination: LabelSelector;
  policy: TrafficPolicy;
}

interface LabelSelector {
  matchLabels: Record<string, string>;
}

interface TrafficPolicy {
  bandwidth: string;    // e.g., "10Mbps"
  latency: string;      // e.g., "50ms"
  jitter: string;       // e.g., "10ms"
  packetLoss: string;   // e.g., "0.5%"
}

interface TrafficControlStatus {
  phase: 'Pending' | 'Running' | 'Succeeded' | 'Failed' | 'Unknown';
  appliedLinks: number;
  conditions?: {
    type: string;
    status: 'True' | 'False' | 'Unknown';
    message?: string;
  }[];
}
```

### 3.3 TSN Related Types (Optional)

```typescript
interface TSNSchedule {
  cycleTime: number;        // Microseconds
  slots: TSNSlot[];
}

interface TSNSlot {
  id: string;
  startTime: number;        // Microseconds
  duration: number;         // Microseconds
  trafficClass: 'ST' | 'BE' | 'AVB';
  linkId: string;
  color: string;
}

interface TimeSyncStatus {
  nodeId: string;
  synced: boolean;
  offset: number;           // Nanoseconds
  lastSyncTime: string;
  grandmasterId: string;
  clockClass: number;       // PTP clock class (0-255)
}
```

---

## 4. Implementation Priority

### P0 - Must Implement (Core Features)

| API | Method | Description |
|-----|------|------|
| `/api/v1/namespaces/{ns}/networktopologies` | GET, POST | Topology list/create |
| `/api/v1/namespaces/{ns}/networktopologies/{name}` | GET, DELETE | Topology detail/delete |
| `/api/v1/namespaces/{ns}/trafficcontrols` | GET, POST | Traffic control list/create |
| `/api/v1/namespaces/{ns}/trafficcontrols/{name}` | GET, PUT, DELETE | Traffic control CRUD |

### P1 - Important (Visualization Features)

| API | Method | Description |
|-----|------|------|
| `/api/v1/namespaces/{ns}/topologies/{name}/nodes` | GET | Get topology nodes |
| `/api/v1/namespaces/{ns}/topologies/{name}/links` | GET | Get topology links |

### P2 - Optional (Monitoring Enhancement)

| API | Method | Description |
|-----|------|------|
| `/api/v1/nodes/{nodeId}/metrics` | GET | Node metrics history |
| `/api/v1/links/{linkId}/metrics` | GET | Link metrics history |
| Prometheus API | GET | Metrics query |

---

## 5. Frontend Mock File Reference

| File Path | Description |
|---------|------|
| `frontend/src/api/client.ts` | Kuro API Mock client |
| `frontend/src/api/mock.ts` | Mock data generator |
| `frontend/src/api/prometheus.ts` | Prometheus client (supports mock/real switch) |
| `frontend/src/api/prometheusMock.ts` | Prometheus Mock implementation |
| `frontend/src/types/api.ts` | Complete type definitions |

---

## 6. Environment Variables

The frontend controls API behavior through the following environment variables:

| Variable Name | Default Value | Description |
|--------|--------|------|
| `VITE_USE_MOCK_API` | `true` | Whether to use Mock Kuro API |
| `VITE_USE_MOCK_PROMETHEUS` | `true` | Whether to use Mock Prometheus |
| `VITE_API_BASE_URL` | `/api/v1` | Kuro API base URL |
| `VITE_PROMETHEUS_URL` | `http://localhost:30091` | Prometheus service address |

---

## 7. Backend Implementation Suggestions

### 7.1 Controller API Server

Implement REST API in `internal/controller/api/server.go`:

```go
// Route example
func (s *Server) setupRoutes(r *mux.Router) {
    api := r.PathPrefix("/api/v1").Subrouter()
    
    // NetworkTopology
    api.HandleFunc("/namespaces/{namespace}/networktopologies", s.listTopologies).Methods("GET")
    api.HandleFunc("/namespaces/{namespace}/networktopologies", s.createTopology).Methods("POST")
    api.HandleFunc("/namespaces/{namespace}/networktopologies/{name}", s.getTopology).Methods("GET")
    api.HandleFunc("/namespaces/{namespace}/networktopologies/{name}", s.deleteTopology).Methods("DELETE")
    
    // TrafficControl
    api.HandleFunc("/namespaces/{namespace}/trafficcontrols", s.listTrafficControls).Methods("GET")
    api.HandleFunc("/namespaces/{namespace}/trafficcontrols", s.createTrafficControl).Methods("POST")
    api.HandleFunc("/namespaces/{namespace}/trafficcontrols/{name}", s.getTrafficControl).Methods("GET")
    api.HandleFunc("/namespaces/{namespace}/trafficcontrols/{name}", s.updateTrafficControl).Methods("PUT")
    api.HandleFunc("/namespaces/{namespace}/trafficcontrols/{name}", s.deleteTrafficControl).Methods("DELETE")
    
    // Topology Visualization
    api.HandleFunc("/namespaces/{namespace}/topologies/{name}/nodes", s.getTopologyNodes).Methods("GET")
    api.HandleFunc("/namespaces/{namespace}/topologies/{name}/links", s.getTopologyLinks).Methods("GET")
}
```

### 7.2 Topology Node/Link Retrieval Logic

```go
// Get topology nodes: Query all Pods created by this NetworkTopology
func (s *Server) getTopologyNodes(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    namespace := vars["namespace"]
    name := vars["name"]
    
    // 1. Get NetworkTopology CRD
    topo := &simulationv1alpha1.NetworkTopology{}
    if err := s.client.Get(r.Context(), client.ObjectKey{Namespace: namespace, Name: name}, topo); err != nil {
        respondError(w, err)
        return
    }
    
    // 2. Query Pods based on NodeGroup labels
    var nodes []TopologyNode
    for _, group := range topo.Spec.NodeGroups {
        pods := &corev1.PodList{}
        labels := group.Labels
        labels["kuro.io/topology"] = name
        labels["kuro.io/node-group"] = group.Name
        
        s.client.List(r.Context(), pods, client.InNamespace(namespace), client.MatchingLabels(labels))
        
        for _, pod := range pods.Items {
            nodes = append(nodes, TopologyNode{
                ID:     string(pod.UID),
                Name:   pod.Name,
                Role:   determineRole(pod.Labels),
                IP:     pod.Status.PodIP,
                Labels: pod.Labels,
                Status: string(pod.Status.Phase),
                GroupID: group.Name,
            })
        }
    }
    
    respondJSON(w, nodes)
}
```

### 7.3 Prometheus Metrics Exposure

Ensure Agent exposes the following metrics in `internal/agent/opsapi/http_service.go`:

```go
// Required metric names
const (
    MetricTrafficBytes   = "kuro_pod_traffic_bytes_total"
    MetricTrafficPackets = "kuro_pod_traffic_packets_total"
    MetricDropBytes      = "kuro_pod_drop_bytes_total"
    MetricDropPackets    = "kuro_pod_drop_packets_total"
    MetricLatencyBucket  = "kuro_pod_latency_seconds_bucket"
    MetricLatencyCount   = "kuro_pod_latency_seconds_count"
    MetricLatencySum     = "kuro_pod_latency_seconds_sum"
)

// Metric labels
var trafficLabels = []string{"pod", "direction", "traffic_type"}
```