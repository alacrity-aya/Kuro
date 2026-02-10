package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"kuro/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// MockAgentManager uses testify/mock to simulate the behavior of AgentManager
type MockAgentManager struct {
	mock.Mock
	// Additionally holds a real fake client for testing Topology
	k8sClient client.Client
}

func (m *MockAgentManager) GetK8sClient() client.Client {
	return m.k8sClient
}

func (m *MockAgentManager) ListAgents() []string {
	args := m.Called()
	return args.Get(0).([]string)
}

// [Fix] Updated Mock method signature, adding the refKey parameter
func (m *MockAgentManager) SendCommand(nodeName string, refKey string, payload any) (string, error) {
	args := m.Called(nodeName, refKey, payload)
	return args.String(0), args.Error(1)
}

func TestHandleGetTopology(t *testing.T) {
	// 1. Prepare Scheme
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)

	// 2. Prepare mock data
	// Note: Namespace must be "kuro-experiment" because this namespace is hardcoded in the handler
	podA := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "drone-x1",
			Namespace: "kuro-experiment", // [Critical Modification]
			Labels: map[string]string{
				"kuro.io/sim-node": "true",
				"app":              "drone",
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.1.1"},
	}
	// Pod B: In default namespace (noise), should not be retrieved
	podB := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "wrong-ns-pod",
			Namespace: "default",
			Labels: map[string]string{
				"kuro.io/sim-node": "true",
				"app":              "drone",
			},
		},
	}

	// 3. Create Fake Client
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(podA, podB).
		Build()

	// 4. Initialize Mock Manager
	mockMgr := new(MockAgentManager)
	mockMgr.k8sClient = fakeClient

	server := NewHTTPServer(mockMgr, 8080)

	// 5. Create request
	req, _ := http.NewRequest("GET", "/api/v1/topology", nil)
	rr := httptest.NewRecorder()

	// 6. Execute
	server.handleGetTopology(rr, req)

	// 7. Verification
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp domain.TopologyResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)

	// Should only return 1 node (drone-x1)
	assert.Len(t, resp.Nodes, 1)
	assert.Equal(t, "drone-x1", resp.Nodes[0].Name)
	assert.Equal(t, "drone", resp.Nodes[0].Group)
}

func TestHandleApplyLinkPolicy(t *testing.T) {
	// 1. Initialize Mock
	mockMgr := new(MockAgentManager)

	// [Critical Modification] Verify if refKey is "manual-api"
	expectedPolicy := domain.LinkPolicy{
		SrcIP:        "1.1.1.1",
		DstIP:        "2.2.2.2",
		BandwidthBps: 1000,
		IsDelete:     false,
	}

	// Expect SendCommand to be called, and the second argument must be "manual-api"
	mockMgr.On("SendCommand", "node-1", "manual-api", expectedPolicy).Return("cmd-uuid-123", nil)

	server := NewHTTPServer(mockMgr, 8080)

	// 2. Construct Request Body
	reqBody := []byte(`{
		"node_name": "node-1",
		"src_ip": "1.1.1.1",
		"dst_ip": "2.2.2.2",
		"bandwidth_limit": 1000
	}`)

	req, _ := http.NewRequest("POST", "/api/v1/policy/link", bytes.NewBuffer(reqBody))
	rr := httptest.NewRecorder()

	// 3. Execute
	server.handleApplyLinkPolicy(rr, req)

	// 4. Verification
	assert.Equal(t, http.StatusOK, rr.Code)
	mockMgr.AssertExpectations(t) // Ensure SendCommand was called correctly

	// Verify returned JSON
	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.Equal(t, "ok", resp["status"])
	assert.Equal(t, "cmd-uuid-123", resp["command_id"])
}

func TestHandleListAgents(t *testing.T) {
	mockMgr := new(MockAgentManager)
	mockMgr.On("ListAgents").Return([]string{"node-1", "node-2"})

	server := NewHTTPServer(mockMgr, 8080)

	req, _ := http.NewRequest("GET", "/api/v1/agents", nil)
	rr := httptest.NewRecorder()

	server.handleListAgents(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp map[string]any
	json.Unmarshal(rr.Body.Bytes(), &resp)

	// JSON number parsing defaults to float64
	assert.Equal(t, 2.0, resp["count"])

	nodes := resp["nodes"].([]any)
	assert.Contains(t, nodes, "node-1")
	assert.Contains(t, nodes, "node-2")
}
