package k8s

import (
	"context"
	"testing"
	"time"

	kurov1alpha1 "kuro/api/crd/v1alpha1"
	"kuro/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// MockAgentManager implements the AgentCommander interface
type MockAgentManager struct {
	mock.Mock
}

func (m *MockAgentManager) SendCommand(nodeName string, refkey string, payload any) (string, error) {
	args := m.Called(nodeName, refkey, payload)
	return args.String(0), args.Error(1)
}

func TestTrafficControlReconciler_Reconcile(t *testing.T) {
	// 0. Setup Logger to view errors during Reconcile
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	// 1. Setup Scheme
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = kurov1alpha1.AddToScheme(scheme)

	// 2. Prepare Mock Data
	srcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "src-pod",
			Namespace: "default",
			Labels:    map[string]string{"app": "drone"},
		},
		Spec:   corev1.PodSpec{NodeName: "node-1"},
		Status: corev1.PodStatus{PodIP: "10.0.1.1"},
	}

	dstPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dst-pod",
			Namespace: "default",
			Labels:    map[string]string{"app": "server"},
		},
		Status: corev1.PodStatus{PodIP: "10.0.1.2"},
	}

	tc := &kurov1alpha1.TrafficControl{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: kurov1alpha1.TrafficControlSpec{
			Source:      metav1.LabelSelector{MatchLabels: map[string]string{"app": "drone"}},
			Destination: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
			Policy: kurov1alpha1.LinkPolicySpec{
				Bandwidth: "10Mbps", // Will be parsed as 10,000,000
				Latency:   "50ms",
			},
		},
	}

	// 3. Setup Fake Client
	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(srcPod, dstPod, tc).
		Build()

	// 4. Setup Mock Manager
	mockMgr := new(MockAgentManager)

	expectedPolicy := domain.LinkPolicy{
		SrcIP:         "10.0.1.1",
		DstIP:         "10.0.1.2",
		BandwidthBps:  10000000, // 10Mbps = 10*1000*1000
		BaseLatencyNs: 50000000, // 50ms
	}

	// Use Run to assert parameter details and ensure a match
	mockMgr.On("SendCommand", "node-1", "test-policy", mock.AnythingOfType("domain.LinkPolicy")).Run(func(args mock.Arguments) {
		p := args.Get(2).(domain.LinkPolicy)
		assert.Equal(t, expectedPolicy.SrcIP, p.SrcIP, "SrcIP mismatch")
		assert.Equal(t, expectedPolicy.DstIP, p.DstIP, "DstIP mismatch")
		assert.Equal(t, expectedPolicy.BaseLatencyNs, p.BaseLatencyNs, "Latency mismatch")
		assert.Equal(t, expectedPolicy.BandwidthBps, p.BandwidthBps, "Bandwidth mismatch")
	}).Return("cmd-id", nil)

	// 5. Run Reconciler
	r := &TrafficControlReconciler{
		Client:       client,
		Scheme:       scheme,
		AgentManager: mockMgr,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "test-policy"},
	}

	_, err := r.Reconcile(context.Background(), req)
	assert.NoError(t, err)

	// 6. Verify Expectations
	mockMgr.AssertExpectations(t)
}

// TestTrafficControlReconciler_Deletion tests that BPF rules are cleaned up when TrafficControl is deleted
func TestTrafficControlReconciler_Deletion(t *testing.T) {
	// Setup Logger
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	// Setup Scheme
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = kurov1alpha1.AddToScheme(scheme)

	// Prepare Mock Data - TrafficControl with DeletionTimestamp and Finalizer
	now := metav1.NewTime(time.Now())
	tc := &kurov1alpha1.TrafficControl{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-policy-delete",
			Namespace:         "default",
			Generation:        1,
			DeletionTimestamp: &now,
			Finalizers:        []string{trafficControlFinalizer},
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

	srcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "src-pod",
			Namespace: "default",
			Labels:    map[string]string{"app": "drone"},
		},
		Spec:   corev1.PodSpec{NodeName: "node-1"},
		Status: corev1.PodStatus{PodIP: "10.0.1.1"},
	}

	dstPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dst-pod",
			Namespace: "default",
			Labels:    map[string]string{"app": "server"},
		},
		Status: corev1.PodStatus{PodIP: "10.0.1.2"},
	}

	// Setup Fake Client
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(srcPod, dstPod, tc).
		Build()

	// Setup Mock Manager - expect delete command
	mockMgr := new(MockAgentManager)

	// Expect a delete policy command (IsDelete = true)
	deleteCommandCalled := false
	mockMgr.On("SendCommand", "node-1", "test-policy-delete", mock.AnythingOfType("domain.LinkPolicy")).Run(func(args mock.Arguments) {
		p := args.Get(2).(domain.LinkPolicy)
		assert.Equal(t, "10.0.1.1", p.SrcIP, "SrcIP mismatch")
		assert.Equal(t, "10.0.1.2", p.DstIP, "DstIP mismatch")
		assert.True(t, p.IsDelete, "IsDelete should be true for deletion")
		deleteCommandCalled = true
	}).Return("cmd-id-delete", nil)

	// Run Reconciler
	r := &TrafficControlReconciler{
		Client:       k8sClient,
		Scheme:       scheme,
		AgentManager: mockMgr,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "test-policy-delete"},
	}

	_, err := r.Reconcile(context.Background(), req)
	assert.NoError(t, err)

	// Verify that delete command was sent
	assert.True(t, deleteCommandCalled, "Delete command should have been sent to agent")

	// Note: In fake client, after finalizer removal, the object may be "deleted"
	// We verify the cleanup happened by checking the mock was called with IsDelete=true

	// Verify mock expectations
	mockMgr.AssertExpectations(t)
}

// TestTrafficControlReconciler_AddsFinalizer tests that finalizer is added on reconciliation
func TestTrafficControlReconciler_AddsFinalizer(t *testing.T) {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = kurov1alpha1.AddToScheme(scheme)

	// TrafficControl without finalizer
	tc := &kurov1alpha1.TrafficControl{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy-finalizer",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: kurov1alpha1.TrafficControlSpec{
			Source:      metav1.LabelSelector{MatchLabels: map[string]string{"app": "drone"}},
			Destination: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
			Policy: kurov1alpha1.LinkPolicySpec{
				Bandwidth: "10Mbps",
			},
		},
	}

	srcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "src-pod",
			Namespace: "default",
			Labels:    map[string]string{"app": "drone"},
		},
		Spec:   corev1.PodSpec{NodeName: "node-1"},
		Status: corev1.PodStatus{PodIP: "10.0.1.1"},
	}

	dstPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dst-pod",
			Namespace: "default",
			Labels:    map[string]string{"app": "server"},
		},
		Status: corev1.PodStatus{PodIP: "10.0.1.2"},
	}

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(srcPod, dstPod, tc).
		Build()

	mockMgr := new(MockAgentManager)
	// Expect policy command (not delete)
	mockMgr.On("SendCommand", "node-1", "test-policy-finalizer", mock.AnythingOfType("domain.LinkPolicy")).Run(func(args mock.Arguments) {
		p := args.Get(2).(domain.LinkPolicy)
		assert.False(t, p.IsDelete, "IsDelete should be false for normal reconciliation")
	}).Return("cmd-id", nil)

	r := &TrafficControlReconciler{
		Client:       k8sClient,
		Scheme:       scheme,
		AgentManager: mockMgr,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "test-policy-finalizer"},
	}

	// First reconcile - should add finalizer
	_, err := r.Reconcile(context.Background(), req)
	assert.NoError(t, err)

	// Verify finalizer was added
	updatedTC := &kurov1alpha1.TrafficControl{}
	err = k8sClient.Get(context.Background(), req.NamespacedName, updatedTC)
	assert.NoError(t, err)
	assert.Contains(t, updatedTC.Finalizers, trafficControlFinalizer, "Finalizer should be added")

	mockMgr.AssertExpectations(t)
}
