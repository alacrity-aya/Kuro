package controller

import (
	"context"
	"log/slog"

	"github.com/alacrity-aya/Kuro/internal/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
)

// WorkloadReconciler is responsible for reconciling ExperimentWorkload objects.
type WorkloadReconciler struct {
	KubeClient kubernetes.Interface
	Logger     *slog.Logger
}

func NewWorkloadReconciler(client kubernetes.Interface, logger *slog.Logger) *WorkloadReconciler {
	return &WorkloadReconciler{
		KubeClient: client,
		Logger:     logger.With("controller", "WorkloadReconciler"),
	}
}

// Reconcile is the core loop: receives a Workload object and ensures K8s resources exist.
func (r *WorkloadReconciler) Reconcile(workload *v1alpha1.ExperimentWorkload) error {
	r.Logger.Info("Starting reconciliation for Workload", "name", workload.Name, "namespace", workload.Namespace)

	// Iterate through each component defined by the user
	for _, comp := range workload.Spec.Components {
		// 1. Ensure Headless Service exists (for network visibility)
		if err := r.ensureService(workload, comp); err != nil {
			return err
		}

		// 2. Ensure StatefulSet exists (for pod creation)
		if err := r.ensureStatefulSet(workload, comp); err != nil {
			return err
		}
	}
	return nil
}

// ensureService creates a Headless Service for the component.
func (r *WorkloadReconciler) ensureService(owner *v1alpha1.ExperimentWorkload, comp v1alpha1.Component) error {
	svcName := comp.Name // Service name uses component name, e.g., "drone-leader"

	// Define the desired Service object
	desiredSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      svcName,
			Namespace: owner.Namespace,
			// [Key Point] Set OwnerReference for cascading deletion
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(owner, schema.GroupVersionKind{
					Group:   "kuro.io",
					Version: "v1alpha1",
					Kind:    "ExperimentWorkload",
				}),
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "None", // Headless Service
			Selector: map[string]string{
				"kuro-component": comp.Name,
				"kuro-workload":  owner.Name,
			},
			Ports: []corev1.ServicePort{
				{Name: "dummy", Port: 80}, // At least one port is required
			},
		},
	}

	// Call K8s API to create the service
	_, err := r.KubeClient.CoreV1().Services(owner.Namespace).Create(context.TODO(), desiredSvc, metav1.CreateOptions{})
	if errors.IsAlreadyExists(err) {
		// TODO: Already exists; in production, you might need an Update logic here.
		// Skipping for simplification.
		return nil
	}
	if err == nil {
		r.Logger.Info("Successfully created Service", "service_name", svcName)
	}
	return err
}

// ensureStatefulSet creates a StatefulSet for the component.
func (r *WorkloadReconciler) ensureStatefulSet(owner *v1alpha1.ExperimentWorkload, comp v1alpha1.Component) error {
	stsName := comp.Name // STS name, pods will be named stsName-0, stsName-1, etc.
	replicas := comp.Replicas

	// Construct Container Resources
	resReq := corev1.ResourceRequirements{
		Limits:   make(corev1.ResourceList),
		Requests: make(corev1.ResourceList),
	}
	if comp.Resources.Limits != nil {
		if cpu, ok := comp.Resources.Limits["cpu"]; ok {
			resReq.Limits[corev1.ResourceCPU] = resource.MustParse(cpu)
		}
		if mem, ok := comp.Resources.Limits["memory"]; ok {
			resReq.Limits[corev1.ResourceMemory] = resource.MustParse(mem)
		}
	}

	// Construct Environment Variables
	var envVars []corev1.EnvVar
	for k, v := range comp.Env {
		envVars = append(envVars, corev1.EnvVar{Name: k, Value: v})
	}

	// Define the desired StatefulSet object
	desiredSts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      stsName,
			Namespace: owner.Namespace,
			// [Key Point] Cascading deletion
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(owner, schema.GroupVersionKind{
					Group:   "kuro.io",
					Version: "v1alpha1",
					Kind:    "ExperimentWorkload",
				}),
			},
		},
		Spec: appsv1.StatefulSetSpec{
			ServiceName: comp.Name, // Associated with the Headless Service
			Replicas:    &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kuro-component": comp.Name,
					"kuro-workload":  owner.Name,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"kuro-component": comp.Name,
						"kuro-workload":  owner.Name,
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:      "main",
							Image:     comp.Image,
							Command:   comp.Command,
							Args:      comp.Args,
							Env:       envVars,
							Resources: resReq,
							// [Requirement] Inject NET_ADMIN capability for Agent control
							SecurityContext: &corev1.SecurityContext{
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{"NET_ADMIN"},
								},
							},
						},
					},
				},
			},
		},
	}

	_, err := r.KubeClient.AppsV1().StatefulSets(owner.Namespace).Create(context.TODO(), desiredSts, metav1.CreateOptions{})
	if errors.IsAlreadyExists(err) {
		return nil
	}
	if err == nil {
		r.Logger.Info("Successfully created StatefulSet", "sts_name", stsName, "replicas", replicas)
	}
	return err
}
