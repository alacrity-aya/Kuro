# Backend API Implementation Plan

## 1. Current Status Analysis

### 1.1 Existing Infrastructure

| Component | File Path | Status |
|------|---------|------|
| NetworkTopology CRD | `api/crd/v1alpha1/networktopology_types.go` | ✅ Defined |
| TrafficControl CRD | `api/crd/v1alpha1/trafficcontrol_types.go` | ✅ Defined |
| TopologyReconciler | `internal/controller/k8s/topology_controller.go` | ✅ Implemented |
| TrafficControlReconciler | `internal/controller/k8s/traffic_controller.go` | ✅ Implemented |
| HTTP Server | `internal/controller/api/server.go` | ⚠️ Needs Extension |
| Domain Models | `internal/domain/models.go` | ⚠️ Needs Extension |

### 1.2 Existing API Endpoints

```
GET  /api/v1/topology         # Get topology (format doesn't match frontend needs)
GET  /api/v1/agents           # List Agents
POST /api/v1/policy/link      # Manually apply link policy
POST /api/v1/policy/pod       # Manually apply Pod policy
POST /api/v1/policy/node      # Manually apply node policy
```

### 1.3 APIs to Add

| Priority | Endpoint | Method | Description |
|--------|------|------|------|
| P0 | `/api/v1/namespaces/{ns}/networktopologies` | GET, POST | Topology list/create |
| P0 | `/api/v1/namespaces/{ns}/networktopologies/{name}` | GET, DELETE | Topology detail/delete |
| P0 | `/api/v1/namespaces/{ns}/trafficcontrols` | GET, POST | Traffic control list/create |
| P0 | `/api/v1/namespaces/{ns}/trafficcontrols/{name}` | GET, PUT, DELETE | Traffic control CRUD |
| P1 | `/api/v1/namespaces/{ns}/topologies/{name}/nodes` | GET | Topology node list |
| P1 | `/api/v1/namespaces/{ns}/topologies/{name}/links` | GET | Topology link list |

---

## 2. Implementation Plan

### Phase 1: Infrastructure Preparation (Day 1)

#### 1.1 Extend Domain Models

**File**: `internal/domain/models.go`

```go
// New response types

// API response wrapper
type ApiResponse struct {
    Success bool   `json:"success"`
    Data    any    `json:"data,omitempty"`
    Error   string `json:"error,omitempty"`
}

// Paginated list result
type ListResult struct {
    Items       any    `json:"items"`
    TotalCount  int    `json:"totalCount"`
    ContinueToken string `json:"continueToken,omitempty"`
}

// Topology visualization node (extended version)
type TopologyNodeViz struct {
    ID      string            `json:"id"`      // Pod UID
    Name    string            `json:"name"`    // Pod name
    Role    string            `json:"role"`    // Node role: drone, gateway, etc.
    IP      string            `json:"ip"`      // Pod IP
    Labels  map[string]string `json:"labels"`
    Status  string            `json:"status"`  // running, pending, failed
    GroupID string            `json:"groupId"` // NodeGroup name
    X       *int              `json:"x,omitempty"` // Visualization coordinates
    Y       *int              `json:"y,omitempty"`
}

// Topology link
type TopologyLink struct {
    ID       string        `json:"id"`
    SourceID string        `json:"sourceId"`
    TargetID string        `json:"targetId"`
    Policy   *LinkPolicyViz `json:"policy,omitempty"`
    Status   string        `json:"status"` // active, inactive, pending
    Metrics  *LinkMetrics  `json:"metrics,omitempty"`
}

type LinkPolicyViz struct {
    Bandwidth  string `json:"bandwidth"`  // e.g., "10Mbps"
    Latency    string `json:"latency"`    // e.g., "50ms"
    Jitter     string `json:"jitter"`     // e.g., "10ms"
    PacketLoss string `json:"packetLoss"` // e.g., "0.5%"
}

type LinkMetrics struct {
    BandwidthUsage  float64 `json:"bandwidthUsage"`  // 0-100
    CurrentLatency  float64 `json:"currentLatency"`  // ms
    CurrentJitter   float64 `json:"currentJitter"`   // ms
    PacketLossRate  float64 `json:"packetLossRate"`  // 0-100
    BytesPerSecond  float64 `json:"bytesPerSecond"`
    PacketsPerSecond float64 `json:"packetsPerSecond"`
}
```

#### 1.2 Add Response Helper Functions

**File**: `internal/controller/api/server.go`

```go
// Unified response functions
func (s *HTTPServer) respondJSON(w http.ResponseWriter, status int, data any) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    json.NewEncoder(w).Encode(data)
}

func (s *HTTPServer) respondSuccess(w http.ResponseWriter, data any) {
    s.respondJSON(w, http.StatusOK, domain.ApiResponse{
        Success: true,
        Data:    data,
    })
}

func (s *HTTPServer) respondError(w http.ResponseWriter, status int, message string) {
    s.respondJSON(w, status, domain.ApiResponse{
        Success: false,
        Error:   message,
    })
}

// Path parameter parsing
func getPathParam(r *http.Request, key string) string {
    return mux.Vars(r)[key]
}

func getQueryParam(r *http.Request, key, defaultValue string) string {
    if v := r.URL.Query().Get(key); v != "" {
        return v
    }
    return defaultValue
}
```

---

### Phase 2: NetworkTopology API (Day 1-2)

#### 2.1 Implement Routing

**File**: `internal/controller/api/server.go`

```go
import "github.com/gorilla/mux"

func (s *HTTPServer) Run() error {
    r := mux.NewRouter()
    
    // API v1 route group
    api := r.PathPrefix("/api/v1").Subrouter()
    
    // NetworkTopology CRUD
    api.HandleFunc("/namespaces/{namespace}/networktopologies", 
        s.listNetworkTopologies).Methods("GET")
    api.HandleFunc("/namespaces/{namespace}/networktopologies", 
        s.createNetworkTopology).Methods("POST")
    api.HandleFunc("/namespaces/{namespace}/networktopologies/{name}", 
        s.getNetworkTopology).Methods("GET")
    api.HandleFunc("/namespaces/{namespace}/networktopologies/{name}", 
        s.deleteNetworkTopology).Methods("DELETE")
    
    // TrafficControl CRUD (Phase 3)
    // ...
    
    // Topology Visualization (Phase 4)
    // ...
    
    // Keep existing endpoints (compatibility)
    api.HandleFunc("/topology", s.handleGetTopology).Methods("GET")
    api.HandleFunc("/agents", s.handleListAgents).Methods("GET")
    
    s.server = &http.Server{
        Addr:    fmt.Sprintf(":%d", s.port),
        Handler: r, // Use mux router
    }
    
    return s.server.ListenAndServe()
}
```

#### 2.2 Implement Handlers

```go
// GET /api/v1/namespaces/{namespace}/networktopologies
func (s *HTTPServer) listNetworkTopologies(w http.ResponseWriter, r *http.Request) {
    namespace := getPathParam(r, "namespace")
    
    list := &v1alpha1.NetworkTopologyList{}
    opts := []client.ListOption{
        client.InNamespace(namespace),
    }
    
    // Support label filtering
    if labelSelector := getQueryParam(r, "labelSelector", ""); labelSelector != "" {
        selector, err := labels.Parse(labelSelector)
        if err != nil {
            s.respondError(w, http.StatusBadRequest, "invalid label selector")
            return
        }
        opts = append(opts, client.MatchingLabelsSelector{Selector: selector})
    }
    
    if err := s.manager.GetK8sClient().List(r.Context(), list, opts...); err != nil {
        s.respondError(w, http.StatusInternalServerError, err.Error())
        return
    }
    
    s.respondSuccess(w, domain.ListResult{
        Items:      list.Items,
        TotalCount: len(list.Items),
    })
}

// GET /api/v1/namespaces/{namespace}/networktopologies/{name}
func (s *HTTPServer) getNetworkTopology(w http.ResponseWriter, r *http.Request) {
    namespace := getPathParam(r, "namespace")
    name := getPathParam(r, "name")
    
    topo := &v1alpha1.NetworkTopology{}
    if err := s.manager.GetK8sClient().Get(r.Context(), 
        client.ObjectKey{Namespace: namespace, Name: name}, topo); err != nil {
        if errors.IsNotFound(err) {
            s.respondError(w, http.StatusNotFound, "networktopology not found")
        } else {
            s.respondError(w, http.StatusInternalServerError, err.Error())
        }
        return
    }
    
    s.respondSuccess(w, topo)
}

// POST /api/v1/namespaces/{namespace}/networktopologies
func (s *HTTPServer) createNetworkTopology(w http.ResponseWriter, r *http.Request) {
    namespace := getPathParam(r, "namespace")
    
    var req NetworkTopologyCreateRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        s.respondError(w, http.StatusBadRequest, "invalid JSON")
        return
    }
    
    // Build CRD object
    topo := &v1alpha1.NetworkTopology{
        ObjectMeta: metav1.ObjectMeta{
            Name:      req.Name,
            Namespace: namespace,
            Labels:    req.Labels,
        },
        Spec: v1alpha1.NetworkTopologySpec{
            NodeGroups: convertNodeGroups(req.Spec.NodeGroups),
        },
    }
    
    if err := s.manager.GetK8sClient().Create(r.Context(), topo); err != nil {
        s.respondError(w, http.StatusInternalServerError, err.Error())
        return
    }
    
    s.respondJSON(w, http.StatusCreated, domain.ApiResponse{
        Success: true,
        Data:    topo,
    })
}

// DELETE /api/v1/namespaces/{namespace}/networktopologies/{name}
func (s *HTTPServer) deleteNetworkTopology(w http.ResponseWriter, r *http.Request) {
    namespace := getPathParam(r, "namespace")
    name := getPathParam(r, "name")
    
    topo := &v1alpha1.NetworkTopology{
        ObjectMeta: metav1.ObjectMeta{
            Name:      name,
            Namespace: namespace,
        },
    }
    
    if err := s.manager.GetK8sClient().Delete(r.Context(), topo); err != nil {
        if errors.IsNotFound(err) {
            s.respondError(w, http.StatusNotFound, "networktopology not found")
        } else {
            s.respondError(w, http.StatusInternalServerError, err.Error())
        }
        return
    }
    
    s.respondSuccess(w, nil)
}
```

---

### Phase 3: TrafficControl API (Day 2-3)

#### 3.1 Implement Handlers

```go
// GET /api/v1/namespaces/{namespace}/trafficcontrols
func (s *HTTPServer) listTrafficControls(w http.ResponseWriter, r *http.Request) {
    namespace := getPathParam(r, "namespace")
    
    list := &v1alpha1.TrafficControlList{}
    opts := []client.ListOption{
        client.InNamespace(namespace),
    }
    
    if labelSelector := getQueryParam(r, "labelSelector", ""); labelSelector != "" {
        selector, err := labels.Parse(labelSelector)
        if err != nil {
            s.respondError(w, http.StatusBadRequest, "invalid label selector")
            return
        }
        opts = append(opts, client.MatchingLabelsSelector{Selector: selector})
    }
    
    if err := s.manager.GetK8sClient().List(r.Context(), list, opts...); err != nil {
        s.respondError(w, http.StatusInternalServerError, err.Error())
        return
    }
    
    s.respondSuccess(w, domain.ListResult{
        Items:      list.Items,
        TotalCount: len(list.Items),
    })
}

// GET /api/v1/namespaces/{namespace}/trafficcontrols/{name}
func (s *HTTPServer) getTrafficControl(w http.ResponseWriter, r *http.Request) {
    namespace := getPathParam(r, "namespace")
    name := getPathParam(r, "name")
    
    tc := &v1alpha1.TrafficControl{}
    if err := s.manager.GetK8sClient().Get(r.Context(), 
        client.ObjectKey{Namespace: namespace, Name: name}, tc); err != nil {
        if errors.IsNotFound(err) {
            s.respondError(w, http.StatusNotFound, "trafficcontrol not found")
        } else {
            s.respondError(w, http.StatusInternalServerError, err.Error())
        }
        return
    }
    
    s.respondSuccess(w, tc)
}

// POST /api/v1/namespaces/{namespace}/trafficcontrols
func (s *HTTPServer) createTrafficControl(w http.ResponseWriter, r *http.Request) {
    namespace := getPathParam(r, "namespace")
    
    var req TrafficControlCreateRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        s.respondError(w, http.StatusBadRequest, "invalid JSON")
        return
    }
    
    tc := &v1alpha1.TrafficControl{
        ObjectMeta: metav1.ObjectMeta{
            Name:      req.Name,
            Namespace: namespace,
            Labels:    req.Labels,
        },
        Spec: v1alpha1.TrafficControlSpec{
            Source:      req.Spec.Source,
            Destination: req.Spec.Destination,
            Policy: v1alpha1.LinkPolicySpec{
                Bandwidth:  req.Spec.Policy.Bandwidth,
                Latency:    req.Spec.Policy.Latency,
                Jitter:     req.Spec.Policy.Jitter,
                PacketLoss: req.Spec.Policy.PacketLoss,
            },
        },
    }
    
    if err := s.manager.GetK8sClient().Create(r.Context(), tc); err != nil {
        s.respondError(w, http.StatusInternalServerError, err.Error())
        return
    }
    
    s.respondJSON(w, http.StatusCreated, domain.ApiResponse{
        Success: true,
        Data:    tc,
    })
}

// PUT /api/v1/namespaces/{namespace}/trafficcontrols/{name}
func (s *HTTPServer) updateTrafficControl(w http.ResponseWriter, r *http.Request) {
    namespace := getPathParam(r, "namespace")
    name := getPathParam(r, "name")
    
    var req TrafficControlUpdateRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        s.respondError(w, http.StatusBadRequest, "invalid JSON")
        return
    }
    
    // Get existing object
    tc := &v1alpha1.TrafficControl{}
    if err := s.manager.GetK8sClient().Get(r.Context(), 
        client.ObjectKey{Namespace: namespace, Name: name}, tc); err != nil {
        if errors.IsNotFound(err) {
            s.respondError(w, http.StatusNotFound, "trafficcontrol not found")
        } else {
            s.respondError(w, http.StatusInternalServerError, err.Error())
        }
        return
    }
    
    // Update Spec
    tc.Spec.Source = req.Spec.Source
    tc.Spec.Destination = req.Spec.Destination
    tc.Spec.Policy = v1alpha1.LinkPolicySpec{
        Bandwidth:  req.Spec.Policy.Bandwidth,
        Latency:    req.Spec.Policy.Latency,
        Jitter:     req.Spec.Policy.Jitter,
        PacketLoss: req.Spec.Policy.PacketLoss,
    }
    
    if err := s.manager.GetK8sClient().Update(r.Context(), tc); err != nil {
        s.respondError(w, http.StatusInternalServerError, err.Error())
        return
    }
    
    s.respondSuccess(w, tc)
}

// DELETE /api/v1/namespaces/{namespace}/trafficcontrols/{name}
func (s *HTTPServer) deleteTrafficControl(w http.ResponseWriter, r *http.Request) {
    namespace := getPathParam(r, "namespace")
    name := getPathParam(r, "name")
    
    tc := &v1alpha1.TrafficControl{
        ObjectMeta: metav1.ObjectMeta{
            Name:      name,
            Namespace: namespace,
        },
    }
    
    if err := s.manager.GetK8sClient().Delete(r.Context(), tc); err != nil {
        if errors.IsNotFound(err) {
            s.respondError(w, http.StatusNotFound, "trafficcontrol not found")
        } else {
            s.respondError(w, http.StatusInternalServerError, err.Error())
        }
        return
    }
    
    s.respondSuccess(w, nil)
}
```

---

### Phase 4: Topology Visualization API (Day 3-4)

#### 4.1 Get Topology Nodes

```go
// GET /api/v1/namespaces/{namespace}/topologies/{name}/nodes
func (s *HTTPServer) getTopologyNodes(w http.ResponseWriter, r *http.Request) {
    namespace := getPathParam(r, "namespace")
    topoName := getPathParam(r, "name")
    
    // 1. Get NetworkTopology CRD
    topo := &v1alpha1.NetworkTopology{}
    if err := s.manager.GetK8sClient().Get(r.Context(), 
        client.ObjectKey{Namespace: namespace, Name: topoName}, topo); err != nil {
        if errors.IsNotFound(err) {
            s.respondError(w, http.StatusNotFound, "topology not found")
        } else {
            s.respondError(w, http.StatusInternalServerError, err.Error())
        }
        return
    }
    
    // 2. Build Pod query labels
    // Pods are created by TopologyReconciler with labels: kuro.io/topology, kuro.io/node-group
    nodes := []domain.TopologyNodeViz{}
    
    for _, group := range topo.Spec.NodeGroups {
        // Query all Pods for this NodeGroup
        podList := &corev1.PodList{}
        opts := []client.ListOption{
            client.InNamespace(namespace),
            client.MatchingLabels{
                "kuro.io/topology":    topoName,
                "kuro.io/node-group":  group.Name,
            },
        }
        
        if err := s.manager.GetK8sClient().List(r.Context(), podList, opts...); err != nil {
            log.Printf("[API] Failed to list pods for group %s: %v", group.Name, err)
            continue
        }
        
        // Determine node role
        role := determineRole(group.Labels)
        
        for _, pod := range podList.Items {
            node := domain.TopologyNodeViz{
                ID:      string(pod.UID),
                Name:    pod.Name,
                Role:    role,
                IP:      pod.Status.PodIP,
                Labels:  pod.Labels,
                Status:  strings.ToLower(string(pod.Status.Phase)),
                GroupID: group.Name,
            }
            nodes = append(nodes, node)
        }
    }
    
    s.respondSuccess(w, nodes)
}

// Determine role from labels
func determineRole(labels map[string]string) string {
    if role, ok := labels["role"]; ok {
        return role
    }
    if app, ok := labels["app"]; ok {
        return app
    }
    return "custom"
}
```

#### 4.2 Get Topology Links

```go
// GET /api/v1/namespaces/{namespace}/topologies/{name}/links
func (s *HTTPServer) getTopologyLinks(w http.ResponseWriter, r *http.Request) {
    namespace := getPathParam(r, "namespace")
    topoName := getPathParam(r, "name")
    
    // 1. Get all TrafficControls
    tcList := &v1alpha1.TrafficControlList{}
    if err := s.manager.GetK8sClient().List(r.Context(), tcList, 
        client.InNamespace(namespace)); err != nil {
        s.respondError(w, http.StatusInternalServerError, err.Error())
        return
    }
    
    // 2. Get all Pods in the topology (for matching)
    podList := &corev1.PodList{}
    if err := s.manager.GetK8sClient().List(r.Context(), podList,
        client.InNamespace(namespace),
        client.MatchingLabels{"kuro.io/topology": topoName}); err != nil {
        s.respondError(w, http.StatusInternalServerError, err.Error())
        return
    }
    
    // 3. Build Pod list and IP -> Pod mapping
    podMap := make(map[string]corev1.Pod) // IP -> Pod
    for _, pod := range podList.Items {
        if pod.Status.PodIP != "" {
            podMap[pod.Status.PodIP] = pod
        }
    }
    
    // 4. Build link list
    links := []domain.TopologyLink{}
    linkID := 0
    
    for _, tc := range tcList.Items {
        srcSelector, _ := metav1.LabelSelectorAsSelector(&tc.Spec.Source)
        dstSelector, _ := metav1.LabelSelectorAsSelector(&tc.Spec.Destination)
        
        // Find all matching source and destination Pods
        for srcIP, srcPod := range podMap {
            if !srcSelector.Matches(labels.Set(srcPod.Labels)) {
                continue
            }
            
            for dstIP, dstPod := range podMap {
                if srcIP == dstIP {
                    continue
                }
                if !dstSelector.Matches(labels.Set(dstPod.Labels)) {
                    continue
                }
                
                link := domain.TopologyLink{
                    ID:       fmt.Sprintf("link-%d", linkID),
                    SourceID: string(srcPod.UID),
                    TargetID: string(dstPod.UID),
                    Policy: &domain.LinkPolicyViz{
                        Bandwidth:  tc.Spec.Policy.Bandwidth,
                        Latency:    tc.Spec.Policy.Latency,
                        Jitter:     tc.Spec.Policy.Jitter,
                        PacketLoss: tc.Spec.Policy.PacketLoss,
                    },
                    Status: "active", // Simplified: assume all are active
                }
                
                // If metrics data is available, add (from Prometheus, currently empty)
                // link.Metrics = getLinkMetrics(srcIP, dstIP)
                
                links = append(links, link)
                linkID++
            }
        }
    }
    
    s.respondSuccess(w, links)
}
```

---

### Phase 5: Request Type Definitions (Day 1)

**File**: `internal/controller/api/types.go` (new file)

```go
package api

import (
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ==================
// NetworkTopology
// ==================

type NetworkTopologyCreateRequest struct {
    Name   string            `json:"name"`
    Labels map[string]string `json:"labels,omitempty"`
    Spec   NetworkTopologySpecRequest `json:"spec"`
}

type NetworkTopologySpecRequest struct {
    NodeGroups []NodeGroupRequest `json:"nodeGroups"`
}

type NodeGroupRequest struct {
    Name     string            `json:"name"`
    Replicas int32             `json:"replicas"`
    Image    string            `json:"image"`
    Command  []string          `json:"command,omitempty"`
    Labels   map[string]string `json:"labels,omitempty"`
}

// ==================
// TrafficControl
// ==================

type TrafficControlCreateRequest struct {
    Name   string            `json:"name"`
    Labels map[string]string `json:"labels,omitempty"`
    Spec   TrafficControlSpecRequest `json:"spec"`
}

type TrafficControlUpdateRequest struct {
    Spec TrafficControlSpecRequest `json:"spec"`
}

type TrafficControlSpecRequest struct {
    Source      metav1.LabelSelector `json:"source"`
    Destination metav1.LabelSelector `json:"destination"`
    Policy      LinkPolicyRequest    `json:"policy"`
}

type LinkPolicyRequest struct {
    Bandwidth  string `json:"bandwidth"`
    Latency    string `json:"latency"`
    Jitter     string `json:"jitter"`
    PacketLoss string `json:"packetLoss"`
}
```

---

## 3. File Modification List

| File | Operation | Description |
|------|------|------|
| `internal/controller/api/server.go` | Modify | Refactor routing, add new handlers |
| `internal/controller/api/types.go` | Create | Request type definitions |
| `internal/domain/models.go` | Modify | Add response types |
| `go.mod` | Modify | Add gorilla/mux dependency |

---

## 4. Testing Plan

### 4.1 Unit Tests

```go
// internal/controller/api/server_test.go

func TestListNetworkTopologies(t *testing.T) {
    // Test normal list query
    // Test empty list
    // Test label filtering
}

func TestCreateNetworkTopology(t *testing.T) {
    // Test normal creation
    // Test duplicate name
    // Test invalid request body
}

func TestGetTopologyNodes(t *testing.T) {
    // Test topology not found
    // Test empty node group
    // Test normal node return
}

func TestGetTopologyLinks(t *testing.T) {
    // Test no TrafficControl
    // Test normal link generation
}
```

### 4.2 Integration Tests

```bash
# Create topology
curl -X POST http://localhost:8080/api/v1/namespaces/default/networktopologies \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-topology",
    "spec": {
      "nodeGroups": [
        {"name": "drones", "replicas": 3, "image": "nginx", "labels": {"role": "drone"}}
      ]
    }
  }'

# Query topology
curl http://localhost:8080/api/v1/namespaces/default/networktopologies

# Create traffic control
curl -X POST http://localhost:8080/api/v1/namespaces/default/trafficcontrols \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-tc",
    "spec": {
      "source": {"matchLabels": {"role": "drone"}},
      "destination": {"matchLabels": {"role": "ground"}},
      "policy": {"bandwidth": "10Mbps", "latency": "50ms"}
    }
  }'

# Query nodes
curl http://localhost:8080/api/v1/namespaces/default/topologies/test-topology/nodes

# Query links
curl http://localhost:8080/api/v1/namespaces/default/topologies/test-topology/links
```

---

## 5. Frontend Integration

### 5.1 Environment Variable Configuration

```bash
# frontend/.env.local
VITE_USE_MOCK_API=false
VITE_API_BASE_URL=/api/v1
VITE_PROMETHEUS_URL=http://localhost:30091
```

### 5.2 Modify Frontend client.ts

```typescript
// frontend/src/api/client.ts

// Replace MockKuroApiClient with real implementation
export class KuroApiClient implements KuroApiClientInterface {
  private baseUrl: string;

  constructor() {
    this.baseUrl = import.meta.env.VITE_API_BASE_URL || '/api/v1';
  }

  async listTopologies(namespace: string): Promise<ApiResponse<ListResult<NetworkTopology>>> {
    const response = await fetch(`${this.baseUrl}/namespaces/${namespace}/networktopologies`);
    return response.json();
  }

  // ... other method implementations
}
```

---

## 6. Time Estimation

| Phase | Effort | Description |
|------|--------|------|
| Phase 1: Infrastructure | 0.5 day | Domain models, response functions |
| Phase 2: NetworkTopology API | 1 day | CRUD implementation + testing |
| Phase 3: TrafficControl API | 1 day | CRUD implementation + testing |
| Phase 4: Visualization API | 1 day | nodes/links implementation |
| Phase 5: Testing & Integration | 1 day | Integration testing, frontend integration |
| **Total** | **4.5 days** | |

---

## 7. Dependency Check

```bash
# Ensure gorilla/mux is installed
go get github.com/gorilla/mux

# Ensure CRD definitions exist
ls api/crd/v1alpha1/

# Ensure controller-runtime is available
grep "sigs.k8s.io/controller-runtime" go.mod
```