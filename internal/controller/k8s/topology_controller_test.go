package k8s

import (
	"context"
	"testing"

	kurov1alpha1 "kuro/api/crd/v1alpha1"

	"github.com/stretchr/testify/assert"
	appsv1 "k8s.io/api/apps/v1"
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

func TestTopologyReconciler_CreateDeployment(t *testing.T) {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = kurov1alpha1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	topology := &kurov1alpha1.NetworkTopology{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-topology",
			Namespace: "kuro-experiment",
		},
		Spec: kurov1alpha1.NetworkTopologySpec{
			NodeGroups: []kurov1alpha1.NodeGroup{
				{
					Name:     "drones",
					Replicas: 3,
					Image:    "python:3.11",
					Labels: map[string]string{
						"role": "drone",
					},
					Command: []string{"/bin/sh", "-c", "sleep 3600"},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(topology).
		Build()

	r := &TopologyReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "kuro-experiment",
			Name:      "test-topology",
		},
	}

	_, err := r.Reconcile(context.Background(), req)
	assert.NoError(t, err)

	// Verify Deployment was created
	deploy := &appsv1.Deployment{}
	err = fakeClient.Get(context.Background(), types.NamespacedName{
		Namespace: "kuro-experiment",
		Name:      "test-topology-drones",
	}, deploy)
	assert.NoError(t, err, "Deployment should be created")

	// Verify Deployment spec
	assert.Equal(t, int32(3), *deploy.Spec.Replicas, "Replicas should be 3")
	assert.Equal(t, "drones", deploy.Labels["app"], "App label should be set")
	assert.Equal(t, "true", deploy.Labels["kuro.io/sim-node"], "Sim-node label should be set")
	assert.Equal(t, "drone", deploy.Labels["role"], "Custom role label should be set")

	// Verify container spec
	assert.Len(t, deploy.Spec.Template.Spec.Containers, 1, "Should have 1 container")
	assert.Equal(t, "main", deploy.Spec.Template.Spec.Containers[0].Name)
	assert.Equal(t, "python:3.11", deploy.Spec.Template.Spec.Containers[0].Image)
	assert.Equal(t, []string{"/bin/sh", "-c", "sleep 3600"}, deploy.Spec.Template.Spec.Containers[0].Command)

	// Verify OwnerReference for cascading delete
	assert.Len(t, deploy.OwnerReferences, 1, "Should have owner reference")
	assert.Equal(t, "NetworkTopology", deploy.OwnerReferences[0].Kind)
	assert.Equal(t, "test-topology", deploy.OwnerReferences[0].Name)
}

func TestTopologyReconciler_CreateConfigMap(t *testing.T) {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = kurov1alpha1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	topology := &kurov1alpha1.NetworkTopology{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-topology",
			Namespace: "kuro-experiment",
		},
		Spec: kurov1alpha1.NetworkTopologySpec{
			NodeGroups: []kurov1alpha1.NodeGroup{
				{
					Name:     "sensors",
					Replicas: 2,
					Image:    "python:3.11",
					UserProgram: &kurov1alpha1.UserProgram{
						Source:     "print('hello')",
						MountPath:  "/app/main.py",
						Filename:   "main.py",
					},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(topology).
		Build()

	r := &TopologyReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "kuro-experiment",
			Name:      "test-topology",
		},
	}

	_, err := r.Reconcile(context.Background(), req)
	assert.NoError(t, err)

	// Verify ConfigMap was created
	cmList := &corev1.ConfigMapList{}
	err = fakeClient.List(context.Background(), cmList)
	assert.NoError(t, err)
	assert.Len(t, cmList.Items, 1, "ConfigMap should be created")

	cm := cmList.Items[0]
	assert.Contains(t, cm.Data, "main.py", "ConfigMap should contain the program file")
	assert.Equal(t, "print('hello')", cm.Data["main.py"])

	// Verify Deployment has volume mount
	deploy := &appsv1.Deployment{}
	err = fakeClient.Get(context.Background(), types.NamespacedName{
		Namespace: "kuro-experiment",
		Name:      "test-topology-sensors",
	}, deploy)
	assert.NoError(t, err)

	assert.Len(t, deploy.Spec.Template.Spec.Volumes, 1, "Should have volume for user code")
	assert.Len(t, deploy.Spec.Template.Spec.Containers[0].VolumeMounts, 1, "Should mount user code")
	assert.Equal(t, "/app/main.py", deploy.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath)
}

func TestTopologyReconciler_MultipleNodeGroups(t *testing.T) {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = kurov1alpha1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	topology := &kurov1alpha1.NetworkTopology{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "multi-group",
			Namespace: "kuro-experiment",
		},
		Spec: kurov1alpha1.NetworkTopologySpec{
			NodeGroups: []kurov1alpha1.NodeGroup{
				{
					Name:     "drones",
					Replicas: 5,
					Image:    "python:3.11",
					Labels:   map[string]string{"role": "drone"},
				},
				{
					Name:     "stations",
					Replicas: 2,
					Image:    "nginx:latest",
					Labels:   map[string]string{"role": "station"},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(topology).
		Build()

	r := &TopologyReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "kuro-experiment",
			Name:      "multi-group",
		},
	}

	_, err := r.Reconcile(context.Background(), req)
	assert.NoError(t, err)

	// Verify both Deployments were created
	deployList := &appsv1.DeploymentList{}
	err = fakeClient.List(context.Background(), deployList)
	assert.NoError(t, err)
	assert.Len(t, deployList.Items, 2, "Should create 2 Deployments")

	// Verify each deployment
	deployNames := make(map[string]bool)
	for _, d := range deployList.Items {
		deployNames[d.Name] = true
	}
	assert.True(t, deployNames["multi-group-drones"], "drones deployment should exist")
	assert.True(t, deployNames["multi-group-stations"], "stations deployment should exist")
}

func TestTopologyReconciler_TopologyNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = kurov1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	r := &TopologyReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "kuro-experiment",
			Name:      "non-existent",
		},
	}

	result, err := r.Reconcile(context.Background(), req)
	assert.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)
}

func TestTopologyReconciler_OwnerReference(t *testing.T) {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = kurov1alpha1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	topology := &kurov1alpha1.NetworkTopology{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "owner-test",
			Namespace: "kuro-experiment",
		},
		Spec: kurov1alpha1.NetworkTopologySpec{
			NodeGroups: []kurov1alpha1.NodeGroup{
				{
					Name:     "workers",
					Replicas: 1,
					Image:    "busybox:latest",
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(topology).
		Build()

	r := &TopologyReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "kuro-experiment",
			Name:      "owner-test",
		},
	}

	_, err := r.Reconcile(context.Background(), req)
	assert.NoError(t, err)

	// Verify Deployment has correct OwnerReference
	deploy := &appsv1.Deployment{}
	err = fakeClient.Get(context.Background(), types.NamespacedName{
		Namespace: "kuro-experiment",
		Name:      "owner-test-workers",
	}, deploy)
	assert.NoError(t, err)

	assert.Len(t, deploy.OwnerReferences, 1, "Should have owner reference")
	assert.Equal(t, "NetworkTopology", deploy.OwnerReferences[0].Kind)
	assert.Equal(t, "owner-test", deploy.OwnerReferences[0].Name)
	assert.True(t, *deploy.OwnerReferences[0].Controller, "Should be controller reference")
}
