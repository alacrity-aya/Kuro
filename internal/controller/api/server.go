package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "kuro/api/crd/v1alpha1"
	"kuro/internal/domain"
)

type AgentManager interface {
	GetK8sClient() client.Client
	SendCommand(nodeName string, refKey string, payload any) (string, error)
	ListAgents() []string
}

type HTTPServer struct {
	manager AgentManager
	port    int
	server  *http.Server
}

func NewHTTPServer(manager AgentManager, port int) *HTTPServer {
	return &HTTPServer{
		manager: manager,
		port:    port,
	}
}

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
		s.respondError(w, http.StatusInternalServerError, "failed to list NetworkTopologies")
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
			s.respondError(w, http.StatusNotFound, "NetworkTopology not found")
		} else {
			log.Printf("[API] Failed to get NetworkTopology %s/%s: %v", namespace, name, err)
			s.respondError(w, http.StatusInternalServerError, "failed to get NetworkTopology")
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
		s.respondError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	// Input validation
	if req.Name == "" {
		s.respondError(w, http.StatusBadRequest, "name is required")
		return
	}
	for i, ng := range req.Spec.NodeGroups {
		if ng.Name == "" {
			s.respondError(w, http.StatusBadRequest, fmt.Sprintf("nodeGroups[%d].name is required", i))
			return
		}
		if ng.Image == "" {
			s.respondError(w, http.StatusBadRequest, fmt.Sprintf("nodeGroups[%d].image is required", i))
			return
		}
		if ng.Replicas < 0 {
			s.respondError(w, http.StatusBadRequest, fmt.Sprintf("nodeGroups[%d].replicas must be >= 0", i))
			return
		}
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
		log.Printf("[API] Failed to create NetworkTopology %s: %v", req.Name, err)
		s.respondError(w, http.StatusInternalServerError, "failed to create NetworkTopology")
		return
	}

	s.respondCreated(w, topo)
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
			s.respondError(w, http.StatusNotFound, "NetworkTopology not found")
		} else {
			log.Printf("[API] Failed to delete NetworkTopology %s/%s: %v", namespace, name, err)
			s.respondError(w, http.StatusInternalServerError, "failed to delete NetworkTopology")
		}
		return
	}

	s.respondSuccess(w, nil)
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
		s.respondError(w, http.StatusInternalServerError, "failed to list TrafficControls")
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
			s.respondError(w, http.StatusNotFound, "TrafficControl not found")
		} else {
			log.Printf("[API] Failed to get TrafficControl %s/%s: %v", namespace, name, err)
			s.respondError(w, http.StatusInternalServerError, "failed to get TrafficControl")
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
		s.respondError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	// Input validation
	if req.Name == "" {
		s.respondError(w, http.StatusBadRequest, "name is required")
		return
	}
	if len(req.Spec.Source.MatchLabels) == 0 && len(req.Spec.Source.MatchExpressions) == 0 {
		s.respondError(w, http.StatusBadRequest, "spec.source selector is required")
		return
	}
	if len(req.Spec.Destination.MatchLabels) == 0 && len(req.Spec.Destination.MatchExpressions) == 0 {
		s.respondError(w, http.StatusBadRequest, "spec.destination selector is required")
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
		log.Printf("[API] Failed to create TrafficControl %s: %v", req.Name, err)
		s.respondError(w, http.StatusInternalServerError, "failed to create TrafficControl")
		return
	}

	s.respondCreated(w, tc)
}

// PUT /api/v1/namespaces/{namespace}/trafficcontrols/{name}
func (s *HTTPServer) updateTrafficControl(w http.ResponseWriter, r *http.Request) {
	namespace := getPathParam(r, "namespace")
	name := getPathParam(r, "name")

	var req TrafficControlUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	// Input validation
	if len(req.Spec.Source.MatchLabels) == 0 && len(req.Spec.Source.MatchExpressions) == 0 {
		s.respondError(w, http.StatusBadRequest, "spec.source selector is required")
		return
	}
	if len(req.Spec.Destination.MatchLabels) == 0 && len(req.Spec.Destination.MatchExpressions) == 0 {
		s.respondError(w, http.StatusBadRequest, "spec.destination selector is required")
		return
	}

	// Get existing object
	tc := &v1alpha1.TrafficControl{}
	if err := s.manager.GetK8sClient().Get(r.Context(),
		client.ObjectKey{Namespace: namespace, Name: name}, tc); err != nil {
		if errors.IsNotFound(err) {
			s.respondError(w, http.StatusNotFound, "TrafficControl not found")
		} else {
			log.Printf("[API] Failed to get TrafficControl %s/%s for update: %v", namespace, name, err)
			s.respondError(w, http.StatusInternalServerError, "failed to get TrafficControl")
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
		log.Printf("[API] Failed to update TrafficControl %s/%s: %v", namespace, name, err)
		s.respondError(w, http.StatusInternalServerError, "failed to update TrafficControl")
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
			s.respondError(w, http.StatusNotFound, "TrafficControl not found")
		} else {
			log.Printf("[API] Failed to delete TrafficControl %s/%s: %v", namespace, name, err)
			s.respondError(w, http.StatusInternalServerError, "failed to delete TrafficControl")
		}
		return
	}

	s.respondSuccess(w, nil)
}

// =============================================================
// Topology Visualization Handlers (stubs - to be implemented)
// =============================================================

func (s *HTTPServer) getTopologyNodes(w http.ResponseWriter, r *http.Request) {
	s.respondError(w, http.StatusNotImplemented, "not implemented")
}

func (s *HTTPServer) getTopologyLinks(w http.ResponseWriter, r *http.Request) {
	s.respondError(w, http.StatusNotImplemented, "not implemented")
}

// =============================================================
// Legacy Handlers
// =============================================================

// 1. Get topology structure
func (s *HTTPServer) handleGetTopology(w http.ResponseWriter, r *http.Request) {
	k8sClient := s.manager.GetK8sClient()
	if k8sClient == nil {
		http.Error(w, "K8s client not initialized", http.StatusServiceUnavailable)
		return
	}

	podList := &corev1.PodList{}
	opts := []client.ListOption{
		client.InNamespace("kuro-experiment"),
		client.MatchingLabels{"kuro.io/sim-node": "true"},
	}

	if err := k8sClient.List(r.Context(), podList, opts...); err != nil {
		log.Printf("[API] Failed to list pods in kuro-experiment: %v", err)
		http.Error(w, "Failed to fetch topology", http.StatusInternalServerError)
		return
	}

	response := domain.TopologyResponse{
		Nodes: make([]domain.TopologyNode, 0),
	}

	for _, pod := range podList.Items {
		groupName := pod.Labels["app"]
		if groupName == "" {
			groupName = "unknown"
		}

		node := domain.TopologyNode{
			Name:      pod.Name,
			Group:     groupName,
			Namespace: pod.Namespace,
			IP:        pod.Status.PodIP,
			Status:    string(pod.Status.Phase),
		}
		response.Nodes = append(response.Nodes, node)
	}

	s.respondSuccess(w, response)
}

func (s *HTTPServer) handleListAgents(w http.ResponseWriter, r *http.Request) {
	agents := s.manager.ListAgents()
	s.respondSuccess(w, map[string]any{
		"count": len(agents),
		"nodes": agents,
	})
}

func (s *HTTPServer) handleApplyLinkPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NodeName          string `json:"node_name"`
		SrcIP             string `json:"src_ip"`
		DstIP             string `json:"dst_ip"`
		BandwidthLimit    uint64 `json:"bandwidth_limit"`
		BaseLatencyNs     uint64 `json:"base_latency_ns"`
		JitterNs          uint64 `json:"jitter_ns"`
		CorruptionRatePpm uint32 `json:"corruption_rate_ppm"`
		QueueDepthNs      uint64 `json:"queue_depth_ns"`
		IsDelete          bool   `json:"is_delete"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	policy := domain.LinkPolicy{
		SrcIP:             req.SrcIP,
		DstIP:             req.DstIP,
		BandwidthBps:      req.BandwidthLimit,
		BaseLatencyNs:     req.BaseLatencyNs,
		JitterNs:          req.JitterNs,
		CorruptionRatePpm: req.CorruptionRatePpm,
		QueueDepthNs:      req.QueueDepthNs,
		IsDelete:          req.IsDelete,
	}

	cmdID, err := s.manager.SendCommand(req.NodeName, "manual-api", policy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	log.Printf("[API] Applied LinkPolicy on %s", req.NodeName)
	s.respondSuccess(w, map[string]string{"status": "ok", "command_id": cmdID})
}

func (s *HTTPServer) handleApplyPodPolicy(w http.ResponseWriter, r *http.Request) {
	type Rate struct {
		Upload   uint64 `json:"upload"`
		Download uint64 `json:"download"`
	}
	var req struct {
		NodeName  string `json:"node_name"`
		PodName   string `json:"pod_name"`
		Namespace string `json:"namespace"`
		SimRate   *Rate  `json:"sim_rate"`
		SysRate   *Rate  `json:"sys_rate"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	policy := domain.PodPolicy{
		PodName:   req.PodName,
		Namespace: req.Namespace,
	}
	if req.SimRate != nil {
		policy.SimRate = &domain.RateLimit{
			UploadBps:   req.SimRate.Upload,
			DownloadBps: req.SimRate.Download,
		}
	}
	if req.SysRate != nil {
		policy.SysRate = &domain.RateLimit{
			UploadBps:   req.SysRate.Upload,
			DownloadBps: req.SysRate.Download,
		}
	}

	cmdID, err := s.manager.SendCommand(req.NodeName, "manual-api", policy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	s.respondSuccess(w, map[string]string{"status": "ok", "command_id": cmdID})
}

func (s *HTTPServer) handleApplyNodePolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NodeName          string `json:"node_name"`
		IngressLimitBps   uint64 `json:"ingress_limit_bps"`
		IngressBurstBytes uint64 `json:"ingress_burst_bytes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	policy := domain.NodePolicy{
		IngressLimitBps:   req.IngressLimitBps,
		IngressBurstBytes: req.IngressBurstBytes,
	}

	cmdID, err := s.manager.SendCommand(req.NodeName, "manual-api", policy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	s.respondSuccess(w, map[string]string{"status": "ok", "command_id": cmdID})
}