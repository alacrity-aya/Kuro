package controller

import (
	"context"
	"sync"
	"testing"
	"time"

	kurov1alpha1 "kuro/api/crd/v1alpha1"
	"kuro/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// MockAgentSender implements domain.AgentSender
type MockAgentSender struct {
	mock.Mock
}

func (m *MockAgentSender) Send(cmd domain.ControllerCommand) error {
	args := m.Called(cmd)
	return args.Error(0)
}

func (m *MockAgentSender) Close() {
	m.Called()
}

func TestNewControllerManager(t *testing.T) {
	mgr := NewControllerManager(9090, 8080, ":8082")

	assert.NotNil(t, mgr)
	assert.Equal(t, 9090, mgr.grpcPort)
	assert.Equal(t, 8080, mgr.httpPort)
	assert.Equal(t, ":8082", mgr.metricsAddr)
	assert.NotNil(t, mgr.resyncQueue)
	assert.Equal(t, 2*time.Second, mgr.resyncDebounce)
}

func TestEnqueueResync_Dedup(t *testing.T) {
	mgr := NewControllerManager(9090, 8080, ":8082")

	// First enqueue should succeed
	mgr.enqueueResync("node-1")

	// Check pending flag
	_, exists := mgr.resyncPending.Load("node-1")
	assert.True(t, exists, "node-1 should be in pending map")

	// Second enqueue should be deduped (no panic, no duplicate)
	mgr.enqueueResync("node-1")

	// Queue should have exactly 1 item
	assert.Equal(t, 1, len(mgr.resyncQueue), "queue should have exactly 1 item")

	// Drain the queue
	nodeName := <-mgr.resyncQueue
	assert.Equal(t, "node-1", nodeName)

	// Clear pending flag (this is what processResyncBatch does)
	mgr.resyncPending.Delete("node-1")

	// Now enqueue again should work
	mgr.enqueueResync("node-1")
	assert.Equal(t, 1, len(mgr.resyncQueue), "queue should have 1 item after re-enqueue")
}

func TestEnqueueResync_QueueFull(t *testing.T) {
	mgr := NewControllerManager(9090, 8080, ":8082")
	// Replace with small buffer for testing
	mgr.resyncQueue = make(chan string, 2)

	// Fill the queue
	mgr.enqueueResync("node-1")
	mgr.enqueueResync("node-2")

	// This should not block, but should be dropped
	mgr.enqueueResync("node-3")

	// Queue should still have 2 items
	assert.Equal(t, 2, len(mgr.resyncQueue))
}

func TestRegisterAgent_EnqueuesResync(t *testing.T) {
	mgr := NewControllerManager(9090, 8080, ":8082")
	mockSender := new(MockAgentSender)

	mgr.RegisterAgent("node-1", mockSender)

	// Check agent is stored
	_, exists := mgr.activeAgents.Load("node-1")
	assert.True(t, exists, "agent should be stored in activeAgents")

	// Check resync is enqueued
	select {
	case nodeName := <-mgr.resyncQueue:
		assert.Equal(t, "node-1", nodeName)
	case <-time.After(100 * time.Millisecond):
		t.Error("expected resync to be enqueued")
	}
}

func TestProcessResyncBatch_EmptyBatch(t *testing.T) {
	mgr := NewControllerManager(9090, 8080, ":8082")

	// Should not panic with empty batch
	mgr.processResyncBatch(context.Background(), []string{})
}

func TestProcessResyncBatch_DispatchesPolicies(t *testing.T) {
	// Setup scheme
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = kurov1alpha1.AddToScheme(scheme)

	// Create test pods
	srcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "src-pod",
			Namespace: "kuro-experiment",
			Labels:    map[string]string{"app": "drone"},
		},
		Spec:   corev1.PodSpec{NodeName: "node-1"},
		Status: corev1.PodStatus{PodIP: "10.0.1.1"},
	}

	dstPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dst-pod",
			Namespace: "kuro-experiment",
			Labels:    map[string]string{"app": "server"},
		},
		Spec:   corev1.PodSpec{NodeName: "node-2"},
		Status: corev1.PodStatus{PodIP: "10.0.1.2"},
	}

	// Create TrafficControl
	tc := &kurov1alpha1.TrafficControl{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "kuro-experiment",
		},
		Spec: kurov1alpha1.TrafficControlSpec{
			Source:      metav1.LabelSelector{MatchLabels: map[string]string{"app": "drone"}},
			Destination: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
			Policy: kurov1alpha1.LinkPolicySpec{
				Bandwidth: "10Mbps",
				Latency:   "50ms",
			},
		},
	}

	// Setup fake client
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(srcPod, dstPod, tc).
		Build()

	// Create manager with fake client
	mgr := NewControllerManager(9090, 8080, ":8082")
	mgr.k8sClient = fakeClient

	// Setup mock sender for node-1
	mockSender := new(MockAgentSender)
	// Expect Send with domain.ControllerCommand
	mockSender.On("Send", mock.AnythingOfType("domain.ControllerCommand")).Return(nil)
	mgr.activeAgents.Store("node-1", mockSender)

	// Process batch
	mgr.processResyncBatch(context.Background(), []string{"node-1"})

	// Verify Send was called
	mockSender.AssertExpectations(t)
}

func TestStartResyncWorker_BatchTimeout(t *testing.T) {
	mgr := NewControllerManager(9090, 8080, ":8082")
	// Use shorter debounce for testing
	mgr.resyncDebounce = 100 * time.Millisecond

	// Setup minimal fake client
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = kurov1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	mgr.k8sClient = fakeClient

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start worker
	go mgr.startResyncWorker(ctx)

	// Enqueue multiple nodes
	mgr.enqueueResync("node-1")
	mgr.enqueueResync("node-2")
	mgr.enqueueResync("node-3")

	// Wait for debounce + processing
	time.Sleep(200 * time.Millisecond)

	// All pending flags should be cleared
	_, exists1 := mgr.resyncPending.Load("node-1")
	_, exists2 := mgr.resyncPending.Load("node-2")
	_, exists3 := mgr.resyncPending.Load("node-3")

	assert.False(t, exists1, "node-1 pending flag should be cleared")
	assert.False(t, exists2, "node-2 pending flag should be cleared")
	assert.False(t, exists3, "node-3 pending flag should be cleared")
}

func TestStartResyncWorker_ContextCancel(t *testing.T) {
	mgr := NewControllerManager(9090, 8080, ":8082")
	mgr.resyncDebounce = 1 * time.Second // Long debounce

	// Setup minimal fake client
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = kurov1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	mgr.k8sClient = fakeClient

	ctx, cancel := context.WithCancel(context.Background())

	// Start worker
	done := make(chan struct{})
	go func() {
		mgr.startResyncWorker(ctx)
		close(done)
	}()

	// Enqueue a node
	mgr.enqueueResync("node-1")

	// Cancel context immediately
	cancel()

	// Worker should exit
	select {
	case <-done:
		// Good, worker exited
	case <-time.After(1 * time.Second):
		t.Error("worker should exit on context cancel")
	}
}

func TestActiveAgents_ConcurrentAccess(t *testing.T) {
	mgr := NewControllerManager(9090, 8080, ":8082")

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			nodeName := string(rune('a' + id%26))
			mockSender := new(MockAgentSender)
			mgr.activeAgents.Store(nodeName, mockSender)
			mgr.activeAgents.Load(nodeName)
		}(i)
	}

	wg.Wait()
	// Should complete without race conditions
}
