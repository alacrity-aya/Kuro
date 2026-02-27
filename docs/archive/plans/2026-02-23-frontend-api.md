# Frontend-Backend API Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement REST API endpoints for frontend to manage NetworkTopology and TrafficControl CRDs with visualization support.

**Architecture:** Extend existing HTTP server with gorilla/mux router for path parameters. Add 12 new endpoints following Kubernetes-style REST conventions. Response format wraps data in `{success, data, error}` structure.

**Tech Stack:** Go 1.25+, gorilla/mux, controller-runtime client, existing CRD types

---

## Context Files

| File | Purpose |
|------|---------|
| `docs/frontend-backend-api.md` | API specification (read this first) |
| `internal/controller/api/server.go` | Current HTTP server (extend this) |
| `internal/domain/models.go` | Domain types (add response types) |
| `api/crd/v1alpha1/*.go` | CRD type definitions |

---

## Task 1: Add Dependencies

**Files:**
- Modify: `go.mod`

**Step 1: Add gorilla/mux dependency**

Run:
```bash
cd /home/alacrity/work/vibe/Kuro && go get github.com/gorilla/mux
```

Expected: `go: added github.com/gorilla/mux v1.8.1`

**Step 2: Verify dependency**

Run:
```bash
cd /home/alacrity/work/vibe/Kuro && grep gorilla go.mod
```

Expected: `github.com/gorilla/mux v1.8.1`

**Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: add gorilla/mux for REST routing"
```

---

## Task 2: Add Response Types to Domain

**Files:**
- Modify: `internal/domain/models.go`

**Step 1: Add API response wrapper types**

Add to end of `internal/domain/models.go`:

```go
// =======================
// API Response Types
// =======================

// ApiResponse wraps all API responses with success/error status
type ApiResponse struct {
	Success bool   `json:"success"`
	Data    any    `json:"data,omitempty"`
	Error   string `json:"error,omitempty"`
}

// ListResult wraps paginated list responses
type ListResult struct {
	Items         any    `json:"items"`
	TotalCount    int    `json:"totalCount"`
	ContinueToken string `json:"continueToken,omitempty"`
}

// TopologyNodeViz represents a node for visualization
type TopologyNodeViz struct {
	ID      string            `json:"id"`      // Pod UID
	Name    string            `json:"name"`    // Pod name
	Role    string            `json:"role"`    // Node role: drone, gateway, etc.
	IP      string            `json:"ip"`      // Pod IP
	Labels  map[string]string `json:"labels"`
	Status  string            `json:"status"`  // running, pending, failed
	GroupID string            `json:"groupId"` // NodeGroup name
	X       *int              `json:"x,omitempty"`
	Y       *int              `json:"y,omitempty"`
}

// TopologyLink represents a link between two nodes
type TopologyLink struct {
	ID       string         `json:"id"`
	SourceID string         `json:"sourceId"`
	TargetID string         `json:"targetId"`
	Policy   *LinkPolicyViz `json:"policy,omitempty"`
	Status   string         `json:"status"` // active, inactive, pending
	Metrics  *LinkMetrics   `json:"metrics,omitempty"`
}

// LinkPolicyViz represents policy for visualization
type LinkPolicyViz struct {
	Bandwidth  string `json:"bandwidth"`  // e.g., "10Mbps"
	Latency    string `json:"latency"`    // e.g., "50ms"
	Jitter     string `json:"jitter"`     // e.g., "10ms"
	PacketLoss string `json:"packetLoss"` // e.g., "0.5%"
}

// LinkMetrics contains current metrics for a link
type LinkMetrics struct {
	BandwidthUsage   float64 `json:"bandwidthUsage"`   // 0-100
	CurrentLatency   float64 `json:"currentLatency"`   // ms
	CurrentJitter    float64 `json:"currentJitter"`    // ms
	PacketLossRate   float64 `json:"packetLossRate"`   // 0-100
	BytesPerSecond   float64 `json:"bytesPerSecond"`
	PacketsPerSecond float64 `json:"packetsPerSecond"`
}
```

**Step 2: Verify compilation**

Run:
```bash
cd /home/alacrity/work/vibe/Kuro && go build ./internal/domain/...
```

Expected: No errors

**Step 3: Commit**

```bash
git add internal/domain/models.go
git commit -m "feat(domain): add API response types for frontend"
```

---

## Task 3: Create Request Types File

**Files:**
- Create: `internal/controller/api/types.go`

**Step 1: Create request types file**

Create file `internal/controller/api/types.go`:

```go
package api

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ==================
// NetworkTopology
// ==================

// NetworkTopologyCreateRequest is the request body for creating a NetworkTopology
type NetworkTopologyCreateRequest struct {
	Name   string                      `json:"name"`
	Labels map[string]string           `json:"labels,omitempty"`
	Spec   NetworkTopologySpecRequest  `json:"spec"`
}

// NetworkTopologySpecRequest is the spec portion of create request
type NetworkTopologySpecRequest struct {
	NodeGroups []NodeGroupRequest `json:"nodeGroups"`
}

// NodeGroupRequest represents a node group in the request
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

// TrafficControlCreateRequest is the request body for creating a TrafficControl
type TrafficControlCreateRequest struct {
	Name   string                     `json:"name"`
	Labels map[string]string          `json:"labels,omitempty"`
	Spec   TrafficControlSpecRequest  `json:"spec"`
}

// TrafficControlUpdateRequest is the request body for updating a TrafficControl
type TrafficControlUpdateRequest struct {
	Spec TrafficControlSpecRequest `json:"spec"`
}

// TrafficControlSpecRequest is the spec portion of TrafficControl request
type TrafficControlSpecRequest struct {
	Source      metav1.LabelSelector `json:"source"`
	Destination metav1.LabelSelector `json:"destination"`
	Policy      LinkPolicyRequest    `json:"policy"`
}

// LinkPolicyRequest represents link policy in the request
type LinkPolicyRequest struct {
	Bandwidth  string `json:"bandwidth"`
	Latency    string `json:"latency"`
	Jitter     string `json:"jitter"`
	PacketLoss string `json:"packetLoss"`
}
```

**Step 2: Verify compilation**

Run:
```bash
cd /home/alacrity/work/vibe/Kuro && go build ./internal/controller/api/...
```

Expected: No errors

**Step 3: Commit**

```bash
git add internal/controller/api/types.go
git commit -m "feat(api): add request types for CRD endpoints"
```

---

## Task 4: Refactor Router to Use gorilla/mux

**Files:**
- Modify: `internal/controller/api/server.go`

**Step 1: Update imports and Run() method**

Replace the `Run()` method in `internal/controller/api/server.go`:

```go
import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "kuro/api/crd/v1alpha1"
	"kuro/internal/domain"
)

// ... existing struct definitions ...

func (s *HTTPServer) Run() error {
	r := mux.NewRouter()

	// API v1 routes
	api := r.PathPrefix("/api/v1").Subrouter()

	// NetworkTopology CRUD
	api.HandleFunc("/namespaces/{namespace}/networktopologies", s.listNetworkTopologies).Methods("GET")
	api.HandleFunc("/namespaces/{namespace}/networktopologies", s.createNetworkTopology).Methods("POST")
	api.HandleFunc("/namespaces/{namespace}/networktopologies/{name}", s.getNetworkTopology).Methods("GET")
	api.HandleFunc("/namespaces/{namespace}/networktopologies/{name}", s.deleteNetworkTopology).Methods("DELETE")

	// TrafficControl CRUD
	api.HandleFunc("/namespaces/{namespace}/trafficcontrols", s.listTrafficControls).Methods("GET")
	api.HandleFunc("/namespaces/{namespace}/trafficcontrols", s.createTrafficControl).Methods("POST")
	api.HandleFunc("/namespaces/{namespace}/trafficcontrols/{name}", s.getTrafficControl).Methods("GET")
	api.HandleFunc("/namespaces/{namespace}/trafficcontrols/{name}", s.updateTrafficControl).Methods("PUT")
	api.HandleFunc("/namespaces/{namespace}/trafficcontrols/{name}", s.deleteTrafficControl).Methods("DELETE")

	// Topology Visualization
	api.HandleFunc("/namespaces/{namespace}/topologies/{name}/nodes", s.getTopologyNodes).Methods("GET")
	api.HandleFunc("/namespaces/{namespace}/topologies/{name}/links", s.getTopologyLinks).Methods("GET")

	// Legacy endpoints (for backward compatibility)
	api.HandleFunc("/topology", s.handleGetTopology).Methods("GET")
	api.HandleFunc("/agents", s.handleListAgents).Methods("GET")
	api.HandleFunc("/policy/link", s.handleApplyLinkPolicy).Methods("POST")
	api.HandleFunc("/policy/pod", s.handleApplyPodPolicy).Methods("POST")
	api.HandleFunc("/policy/node", s.handleApplyNodePolicy).Methods("POST")

	s.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.port),
		Handler: r,
	}

	log.Printf("[API] HTTP Server listening on :%d", s.port)
	return s.server.ListenAndServe()
}
```

**Step 2: Add helper functions**

Add after the struct definitions, before `Run()`:

```go
// respondJSON sends a JSON response with the given status code
func (s *HTTPServer) respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// respondSuccess sends a successful response
func (s *HTTPServer) respondSuccess(w http.ResponseWriter, data any) {
	s.respondJSON(w, http.StatusOK, domain.ApiResponse{
		Success: true,
		Data:    data,
	})
}

// respondError sends an error response
func (s *HTTPServer) respondError(w http.ResponseWriter, status int, message string) {
	s.respondJSON(w, status, domain.ApiResponse{
		Success: false,
		Error:   message,
	})
}

// respondCreated sends a 201 response with data
func (s *HTTPServer) respondCreated(w http.ResponseWriter, data any) {
	s.respondJSON(w, http.StatusCreated, domain.ApiResponse{
		Success: true,
		Data:    data,
	})
}

// getPathParam extracts a path parameter from the request
func getPathParam(r *http.Request, key string) string {
	return mux.Vars(r)[key]
}

// getQueryParam extracts a query parameter with a default value
func getQueryParam(r *http.Request, key, defaultValue string) string {
	if v := r.URL.Query().Get(key); v != "" {
		return v
	}
	return defaultValue
}
```

**Step 3: Verify compilation**

Run:
```bash
cd /home/alacrity/work/vibe/Kuro && go build ./internal/controller/api/...
```

Expected: No errors (handlers not implemented yet, but router compiles)

**Step 4: Commit**

```bash
git add internal/controller/api/server.go
git commit -m "refactor(api): use gorilla/mux for REST routing"
```

---

## Task 5: Implement NetworkTopology List Handler

**Files:**
- Modify: `internal/controller/api/server.go`

**Step 1: Write the handler**

Add after the helper functions:

```go
// =============================================================
// NetworkTopology Handlers
// =============================================================

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
			s.respondError(w, http.StatusBadRequest, "invalid label selector: "+err.Error())
			return
		}
		opts = append(opts, client.MatchingLabelsSelector{Selector: selector})
	}

	if err := s.manager.GetK8sClient().List(r.Context(), list, opts...); err != nil {
		log.Printf("[API] Failed to list NetworkTopologies: %v", err)
		s.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.respondSuccess(w, domain.ListResult{
		Items:      list.Items,
		TotalCount: len(list.Items),
	})
}
```

**Step 2: Verify compilation**

Run:
```bash
cd /home/alacrity/work/vibe/Kuro && go build ./internal/controller/api/...
```

Expected: No errors

**Step 3: Commit**

```bash
git add internal/controller/api/server.go
git commit -m "feat(api): add NetworkTopology list endpoint"
```

---

## Task 6: Implement NetworkTopology Get Handler

**Files:**
- Modify: `internal/controller/api/server.go`

**Step 1: Write the handler**

Add after `listNetworkTopologies`:

```go
// GET /api/v1/namespaces/{namespace}/networktopologies/{name}
func (s *HTTPServer) getNetworkTopology(w http.ResponseWriter, r *http.Request) {
	namespace := getPathParam(r, "namespace")
	name := getPathParam(r, "name")

	topo := &v1alpha1.NetworkTopology{}
	if err := s.manager.GetK8sClient().Get(r.Context(),
		client.ObjectKey{Namespace: namespace, Name: name}, topo); err != nil {
		if errors.IsNotFound(err) {
			s.respondError(w, http.StatusNotFound, "NetworkTopology not found")
		} else {
			s.respondError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	s.respondSuccess(w, topo)
}
```

**Step 2: Verify compilation**

Run:
```bash
cd /home/alacrity/work/vibe/Kuro && go build ./internal/controller/api/...
```

Expected: No errors

**Step 3: Commit**

```bash
git add internal/controller/api/server.go
git commit -m "feat(api): add NetworkTopology get endpoint"
```

---

## Task 7: Implement NetworkTopology Create Handler

**Files:**
- Modify: `internal/controller/api/server.go`

**Step 1: Write the handler**

Add after `getNetworkTopology`:

```go
// POST /api/v1/namespaces/{namespace}/networktopologies
func (s *HTTPServer) createNetworkTopology(w http.ResponseWriter, r *http.Request) {
	namespace := getPathParam(r, "namespace")

	var req NetworkTopologyCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
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
		log.Printf("[API] Failed to create NetworkTopology: %v", err)
		s.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.respondCreated(w, topo)
}

// convertNodeGroups converts request node groups to CRD node groups
func convertNodeGroups(groups []NodeGroupRequest) []v1alpha1.NodeGroup {
	result := make([]v1alpha1.NodeGroup, len(groups))
	for i, g := range groups {
		result[i] = v1alpha1.NodeGroup{
			Name:     g.Name,
			Replicas: g.Replicas,
			Image:    g.Image,
			Command:  g.Command,
			Labels:   g.Labels,
		}
	}
	return result
}
```

**Step 2: Add missing import**

Ensure `metav1` is imported:

```go
import (
	// ... existing imports ...
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)
```

**Step 3: Verify compilation**

Run:
```bash
cd /home/alacrity/work/vibe/Kuro && go build ./internal/controller/api/...
```

Expected: No errors

**Step 4: Commit**

```bash
git add internal/controller/api/server.go
git commit -m "feat(api): add NetworkTopology create endpoint"
```

---

## Task 8: Implement NetworkTopology Delete Handler

**Files:**
- Modify: `internal/controller/api/server.go`

**Step 1: Write the handler**

Add after `createNetworkTopology`:

```go
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
			s.respondError(w, http.StatusNotFound, "NetworkTopology not found")
		} else {
			s.respondError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	s.respondSuccess(w, nil)
}
```

**Step 2: Verify compilation**

Run:
```bash
cd /home/alacrity/work/vibe/Kuro && go build ./internal/controller/api/...
```

Expected: No errors

**Step 3: Commit**

```bash
git add internal/controller/api/server.go
git commit -m "feat(api): add NetworkTopology delete endpoint"
```

---

## Task 9: Implement TrafficControl List Handler

**Files:**
- Modify: `internal/controller/api/server.go`

**Step 1: Write the handler**

Add after NetworkTopology handlers:

```go
// =============================================================
// TrafficControl Handlers
// =============================================================

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
			s.respondError(w, http.StatusBadRequest, "invalid label selector: "+err.Error())
			return
		}
		opts = append(opts, client.MatchingLabelsSelector{Selector: selector})
	}

	if err := s.manager.GetK8sClient().List(r.Context(), list, opts...); err != nil {
		log.Printf("[API] Failed to list TrafficControls: %v", err)
		s.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.respondSuccess(w, domain.ListResult{
		Items:      list.Items,
		TotalCount: len(list.Items),
	})
}
```

**Step 2: Verify compilation**

Run:
```bash
cd /home/alacrity/work/vibe/Kuro && go build ./internal/controller/api/...
```

Expected: No errors

**Step 3: Commit**

```bash
git add internal/controller/api/server.go
git commit -m "feat(api): add TrafficControl list endpoint"
```

---

## Task 10: Implement TrafficControl Get Handler

**Files:**
- Modify: `internal/controller/api/server.go`

**Step 1: Write the handler**

Add after `listTrafficControls`:

```go
// GET /api/v1/namespaces/{namespace}/trafficcontrols/{name}
func (s *HTTPServer) getTrafficControl(w http.ResponseWriter, r *http.Request) {
	namespace := getPathParam(r, "namespace")
	name := getPathParam(r, "name")

	tc := &v1alpha1.TrafficControl{}
	if err := s.manager.GetK8sClient().Get(r.Context(),
		client.ObjectKey{Namespace: namespace, Name: name}, tc); err != nil {
		if errors.IsNotFound(err) {
			s.respondError(w, http.StatusNotFound, "TrafficControl not found")
		} else {
			s.respondError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	s.respondSuccess(w, tc)
}
```

**Step 2: Verify compilation**

Run:
```bash
cd /home/alacrity/work/vibe/Kuro && go build ./internal/controller/api/...
```

Expected: No errors

**Step 3: Commit**

```bash
git add internal/controller/api/server.go
git commit -m "feat(api): add TrafficControl get endpoint"
```

---

## Task 11: Implement TrafficControl Create Handler

**Files:**
- Modify: `internal/controller/api/server.go`

**Step 1: Write the handler**

Add after `getTrafficControl`:

```go
// POST /api/v1/namespaces/{namespace}/trafficcontrols
func (s *HTTPServer) createTrafficControl(w http.ResponseWriter, r *http.Request) {
	namespace := getPathParam(r, "namespace")

	var req TrafficControlCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
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
		log.Printf("[API] Failed to create TrafficControl: %v", err)
		s.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.respondCreated(w, tc)
}
```

**Step 2: Verify compilation**

Run:
```bash
cd /home/alacrity/work/vibe/Kuro && go build ./internal/controller/api/...
```

Expected: No errors

**Step 3: Commit**

```bash
git add internal/controller/api/server.go
git commit -m "feat(api): add TrafficControl create endpoint"
```

---

## Task 12: Implement TrafficControl Update Handler

**Files:**
- Modify: `internal/controller/api/server.go`

**Step 1: Write the handler**

Add after `createTrafficControl`:

```go
// PUT /api/v1/namespaces/{namespace}/trafficcontrols/{name}
func (s *HTTPServer) updateTrafficControl(w http.ResponseWriter, r *http.Request) {
	namespace := getPathParam(r, "namespace")
	name := getPathParam(r, "name")

	var req TrafficControlUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	// Get existing object
	tc := &v1alpha1.TrafficControl{}
	if err := s.manager.GetK8sClient().Get(r.Context(),
		client.ObjectKey{Namespace: namespace, Name: name}, tc); err != nil {
		if errors.IsNotFound(err) {
			s.respondError(w, http.StatusNotFound, "TrafficControl not found")
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
		log.Printf("[API] Failed to update TrafficControl: %v", err)
		s.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.respondSuccess(w, tc)
}
```

**Step 2: Verify compilation**

Run:
```bash
cd /home/alacrity/work/vibe/Kuro && go build ./internal/controller/api/...
```

Expected: No errors

**Step 3: Commit**

```bash
git add internal/controller/api/server.go
git commit -m "feat(api): add TrafficControl update endpoint"
```

---

## Task 13: Implement TrafficControl Delete Handler

**Files:**
- Modify: `internal/controller/api/server.go`

**Step 1: Write the handler**

Add after `updateTrafficControl`:

```go
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
			s.respondError(w, http.StatusNotFound, "TrafficControl not found")
		} else {
			s.respondError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	s.respondSuccess(w, nil)
}
```

**Step 2: Verify compilation**

Run:
```bash
cd /home/alacrity/work/vibe/Kuro && go build ./internal/controller/api/...
```

Expected: No errors

**Step 3: Commit**

```bash
git add internal/controller/api/server.go
git commit -m "feat(api): add TrafficControl delete endpoint"
```

---

## Task 14: Implement Get Topology Nodes Handler

**Files:**
- Modify: `internal/controller/api/server.go`

**Step 1: Write the handler**

Add after TrafficControl handlers:

```go
// =============================================================
// Topology Visualization Handlers
// =============================================================

// GET /api/v1/namespaces/{namespace}/topologies/{name}/nodes
func (s *HTTPServer) getTopologyNodes(w http.ResponseWriter, r *http.Request) {
	namespace := getPathParam(r, "namespace")
	topoName := getPathParam(r, "name")

	// 1. Get NetworkTopology CRD
	topo := &v1alpha1.NetworkTopology{}
	if err := s.manager.GetK8sClient().Get(r.Context(),
		client.ObjectKey{Namespace: namespace, Name: topoName}, topo); err != nil {
		if errors.IsNotFound(err) {
			s.respondError(w, http.StatusNotFound, "NetworkTopology not found")
		} else {
			s.respondError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	// 2. Query Pods for each NodeGroup
	nodes := []domain.TopologyNodeViz{}

	for _, group := range topo.Spec.NodeGroups {
		podList := &corev1.PodList{}
		opts := []client.ListOption{
			client.InNamespace(namespace),
			client.MatchingLabels{
				"kuro.io/topology":   topoName,
				"kuro.io/node-group": group.Name,
			},
		}

		if err := s.manager.GetK8sClient().List(r.Context(), podList, opts...); err != nil {
			log.Printf("[API] Failed to list pods for group %s: %v", group.Name, err)
			continue
		}

		// Determine role from group labels
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

// determineRole extracts role from labels
func determineRole(lbls map[string]string) string {
	if role, ok := lbls["role"]; ok {
		return role
	}
	if app, ok := lbls["app"]; ok {
		return app
	}
	return "custom"
}
```

**Step 2: Verify compilation**

Run:
```bash
cd /home/alacrity/work/vibe/Kuro && go build ./internal/controller/api/...
```

Expected: No errors

**Step 3: Commit**

```bash
git add internal/controller/api/server.go
git commit -m "feat(api): add topology nodes endpoint for visualization"
```

---

## Task 15: Implement Get Topology Links Handler

**Files:**
- Modify: `internal/controller/api/server.go`

**Step 1: Write the handler**

Add after `getTopologyNodes`:

```go
// GET /api/v1/namespaces/{namespace}/topologies/{name}/links
func (s *HTTPServer) getTopologyLinks(w http.ResponseWriter, r *http.Request) {
	namespace := getPathParam(r, "namespace")
	topoName := getPathParam(r, "name")

	// 1. Get all TrafficControls in namespace
	tcList := &v1alpha1.TrafficControlList{}
	if err := s.manager.GetK8sClient().List(r.Context(), tcList,
		client.InNamespace(namespace)); err != nil {
		s.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 2. Get all Pods in the topology
	podList := &corev1.PodList{}
	if err := s.manager.GetK8sClient().List(r.Context(), podList,
		client.InNamespace(namespace),
		client.MatchingLabels{"kuro.io/topology": topoName}); err != nil {
		s.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 3. Build Pod IP -> Pod mapping
	podMap := make(map[string]corev1.Pod)
	for _, pod := range podList.Items {
		if pod.Status.PodIP != "" {
			podMap[pod.Status.PodIP] = pod
		}
	}

	// 4. Build links from TrafficControls
	links := []domain.TopologyLink{}
	linkID := 0

	for _, tc := range tcList.Items {
		srcSelector, err := metav1.LabelSelectorAsSelector(&tc.Spec.Source)
		if err != nil {
			continue
		}
		dstSelector, err := metav1.LabelSelectorAsSelector(&tc.Spec.Destination)
		if err != nil {
			continue
		}

		// Find all matching source and destination pairs
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
					Status: "active",
				}

				links = append(links, link)
				linkID++
			}
		}
	}

	s.respondSuccess(w, links)
}
```

**Step 2: Verify compilation**

Run:
```bash
cd /home/alacrity/work/vibe/Kuro && go build ./internal/controller/api/...
```

Expected: No errors

**Step 3: Commit**

```bash
git add internal/controller/api/server.go
git commit -m "feat(api): add topology links endpoint for visualization"
```

---

## Task 16: Run All Tests

**Files:**
- Run tests in: `internal/controller/api/`

**Step 1: Run existing tests**

Run:
```bash
cd /home/alacrity/work/vibe/Kuro && go test ./internal/controller/api/... -v
```

Expected: All tests pass

**Step 2: Fix any test failures**

If tests fail due to import changes or other issues, fix them.

**Step 3: Commit any fixes**

```bash
git add -A
git commit -m "fix(api): update tests for new router"
```

---

## Task 17: Build and Verify

**Files:**
- Build: `cmd/controller/main.go`

**Step 1: Build controller binary**

Run:
```bash
cd /home/alacrity/work/vibe/Kuro && go build ./cmd/controller/...
```

Expected: Binary built successfully

**Step 2: Run full test suite**

Run:
```bash
cd /home/alacrity/work/vibe/Kuro && ./scripts/test.sh -std
```

Expected: All tests pass

**Step 3: Final commit**

```bash
git add -A
git commit -m "feat(api): complete frontend-backend API implementation"
```

---

## Summary

| Task | Description | Files Modified |
|------|-------------|----------------|
| 1 | Add gorilla/mux dependency | `go.mod` |
| 2 | Add response types | `internal/domain/models.go` |
| 3 | Create request types | `internal/controller/api/types.go` (new) |
| 4 | Refactor router | `internal/controller/api/server.go` |
| 5-8 | NetworkTopology CRUD | `internal/controller/api/server.go` |
| 9-13 | TrafficControl CRUD | `internal/controller/api/server.go` |
| 14-15 | Topology visualization | `internal/controller/api/server.go` |
| 16 | Run tests | - |
| 17 | Build and verify | - |

---

## New API Endpoints

```
GET    /api/v1/namespaces/{ns}/networktopologies
POST   /api/v1/namespaces/{ns}/networktopologies
GET    /api/v1/namespaces/{ns}/networktopologies/{name}
DELETE /api/v1/namespaces/{ns}/networktopologies/{name}

GET    /api/v1/namespaces/{ns}/trafficcontrols
POST   /api/v1/namespaces/{ns}/trafficcontrols
GET    /api/v1/namespaces/{ns}/trafficcontrols/{name}
PUT    /api/v1/namespaces/{ns}/trafficcontrols/{name}
DELETE /api/v1/namespaces/{ns}/trafficcontrols/{name}

GET    /api/v1/namespaces/{ns}/topologies/{name}/nodes
GET    /api/v1/namespaces/{ns}/topologies/{name}/links
```
