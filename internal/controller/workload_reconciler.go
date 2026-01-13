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

// WorkloadReconciler 负责调和 ExperimentWorkload
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

// Reconcile 是核心循环：接收 Workload 对象 -> 确保 K8s 资源存在
func (r *WorkloadReconciler) Reconcile(workload *v1alpha1.ExperimentWorkload) error {
	r.Logger.Info("开始调和 Workload", "name", workload.Name, "namespace", workload.Namespace)

	// 遍历用户定义的每个组件 (Component)
	for _, comp := range workload.Spec.Components {
		// 1. 确保 Headless Service 存在 (用于网络可见性)
		if err := r.ensureService(workload, comp); err != nil {
			return err
		}

		// 2. 确保 StatefulSet 存在 (用于创建 Pod)
		if err := r.ensureStatefulSet(workload, comp); err != nil {
			return err
		}
	}
	return nil
}

// ensureService 创建 Headless Service
func (r *WorkloadReconciler) ensureService(owner *v1alpha1.ExperimentWorkload, comp v1alpha1.Component) error {
	svcName := comp.Name // 服务名直接用组件名，如 "drone-leader"

	// 定义期望的 Service 对象
	desiredSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      svcName,
			Namespace: owner.Namespace,
			// [关键点] 设置 OwnerReference，实现级联删除
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
				{Name: "dummy", Port: 80}, // 必须至少有一个端口
			},
		},
	}

	// 调用 K8s API 创建
	_, err := r.KubeClient.CoreV1().Services(owner.Namespace).Create(context.TODO(), desiredSvc, metav1.CreateOptions{})
	if errors.IsAlreadyExists(err) {
		// 已经存在，实际生产中可能需要 Update 逻辑，这里简化跳过
		return nil
	}
	if err == nil {
		r.Logger.Info("创建 Service 成功", "service_name", svcName)
	}
	return err
}

// ensureStatefulSet 创建 StatefulSet
func (r *WorkloadReconciler) ensureStatefulSet(owner *v1alpha1.ExperimentWorkload, comp v1alpha1.Component) error {
	stsName := comp.Name // STS 名，Pod 将是 stsName-0, stsName-1
	replicas := comp.Replicas

	// 构造容器 Resources
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

	// 构造环境变量
	var envVars []corev1.EnvVar
	for k, v := range comp.Env {
		envVars = append(envVars, corev1.EnvVar{Name: k, Value: v})
	}

	// 定义期望的 StatefulSet 对象
	desiredSts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      stsName,
			Namespace: owner.Namespace,
			// [关键点] 级联删除
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(owner, schema.GroupVersionKind{
					Group:   "kuro.io",
					Version: "v1alpha1",
					Kind:    "ExperimentWorkload",
				}),
			},
		},
		Spec: appsv1.StatefulSetSpec{
			ServiceName: comp.Name, // 关联 Headless Service
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
							// [需求3] 注入 NET_ADMIN 权限，让 Agent 能控制它
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
		r.Logger.Info("创建 StatefulSet 成功", "sts_name", stsName, "replicas", replicas)
	}
	return err
}
