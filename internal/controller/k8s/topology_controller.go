package k8s

import (
	"context"
	"fmt"
	"hash/fnv"
	"maps"

	kurov1alpha1 "kuro/api/crd/v1alpha1"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// TopologyReconciler reconciles a NetworkTopology object
type TopologyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reconcile reads NetworkTopology and creates the corresponding Deployments
func (r *TopologyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// 1. Fetch the NetworkTopology object
	var topo kurov1alpha1.NetworkTopology
	if err := r.Get(ctx, req.NamespacedName, &topo); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// 2. Iterate through NodeGroups to create resources
	for _, group := range topo.Spec.NodeGroups {
		// A. Handle UserProgram -> ConfigMap
		cmName := ""
		if group.UserProgram != nil {
			cm, err := r.constructConfigMap(&topo, &group)
			if err != nil {
				logger.Error(err, "unable to construct ConfigMap", "group", group.Name)
				return ctrl.Result{}, err
			}

			// Create or Update ConfigMap
			// Simplified logic: Using standard Create/Update pattern
			// Attempt to create; if it exists, update it
			foundCM := &corev1.ConfigMap{}
			err = r.Get(ctx, client.ObjectKey{Name: cm.Name, Namespace: cm.Namespace}, foundCM)
			if err != nil && errors.IsNotFound(err) {
				if err := r.Create(ctx, cm); err != nil {
					return ctrl.Result{}, err
				}
			} else if err == nil {
				foundCM.Data = cm.Data
				if err := r.Update(ctx, foundCM); err != nil {
					return ctrl.Result{}, err
				}
			}
			cmName = cm.Name
		}

		// B. Handle Deployment
		deploy, err := r.constructDeployment(&topo, &group, cmName)
		if err != nil {
			return ctrl.Result{}, err
		}

		// Check if Deployment already exists
		found := &appsv1.Deployment{}
		err = r.Get(ctx, client.ObjectKey{Name: deploy.Name, Namespace: deploy.Namespace}, found)
		if err != nil && errors.IsNotFound(err) {
			logger.Info("Creating Deployment", "name", deploy.Name)
			if err := r.Create(ctx, deploy); err != nil {
				return ctrl.Result{}, err
			}
		} else if err == nil {
			// Update logic (e.g., check for changes in replicas or image)
			if *found.Spec.Replicas != *deploy.Spec.Replicas {
				found.Spec.Replicas = deploy.Spec.Replicas
				r.Update(ctx, found)
			}
			// Note: Add image or command update logic here if needed
		}
	}

	// 3. Update status
	if err := r.updateStatus(ctx, &topo); err != nil {
		logger.Error(err, "unable to update NetworkTopology status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *TopologyReconciler) constructConfigMap(topo *kurov1alpha1.NetworkTopology, group *kurov1alpha1.NodeGroup) (*corev1.ConfigMap, error) {
	name := fmt.Sprintf("%s-%s-cfg", topo.Name, group.Name)

	// Generate a Hash to support rolling updates (Optional)
	h := fnv.New32a()
	h.Write([]byte(group.UserProgram.Source))
	name = fmt.Sprintf("%s-%d", name, h.Sum32())

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: topo.Namespace,
			Labels:    group.Labels,
		},
		Data: map[string]string{
			group.UserProgram.Filename: group.UserProgram.Source,
		},
	}

	// Set OwnerReference for automatic cleanup
	if err := ctrl.SetControllerReference(topo, cm, r.Scheme); err != nil {
		return nil, err
	}
	return cm, nil
}

func (r *TopologyReconciler) constructDeployment(topo *kurov1alpha1.NetworkTopology, group *kurov1alpha1.NodeGroup, cmName string) (*appsv1.Deployment, error) {
	labels := make(map[string]string)
	maps.Copy(labels, group.Labels)
	// Inject critical labels for Agent identification and API queries
	labels["kuro.io/sim-node"] = "true"
	labels["kuro.io/topology"] = topo.Name
	labels["kuro.io/node-group"] = group.Name
	labels["app"] = group.Name

	replicas := group.Replicas
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", topo.Name, group.Name),
			Namespace: topo.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:    "main",
						Image:   group.Image,
						Command: group.Command,
					}},
				},
			},
		},
	}

	// Mount the ConfigMap if UserProgram is provided
	if cmName != "" && group.UserProgram != nil {
		dep.Spec.Template.Spec.Volumes = []corev1.Volume{{
			Name: "user-code",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: cmName},
				},
			},
		}}
		dep.Spec.Template.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{
			Name:      "user-code",
			MountPath: group.UserProgram.MountPath, // e.g., /app/ (Note: Mounting a directory)
			SubPath:   group.UserProgram.Filename,  // Use SubPath to mount as an individual file
		}}
	}

	// Set OwnerReference for automatic cleanup
	if err := ctrl.SetControllerReference(topo, dep, r.Scheme); err != nil {
		return nil, err
	}
	return dep, nil
}

func (r *TopologyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&kurov1alpha1.NetworkTopology{}).
		Owns(&appsv1.Deployment{}). // Automatically re-trigger reconcile if deployment is deleted
		Complete(r)
}

// updateStatus calculates and updates the NetworkTopology status
func (r *TopologyReconciler) updateStatus(ctx context.Context, topo *kurov1alpha1.NetworkTopology) error {
	// Calculate total expected nodes
	totalNodes := int32(0)
	readyNodes := int32(0)

	for _, group := range topo.Spec.NodeGroups {
		totalNodes += int32(group.Replicas)

		// Get deployment status
		deployName := fmt.Sprintf("%s-%s", topo.Name, group.Name)
		deploy := &appsv1.Deployment{}
		if err := r.Get(ctx, client.ObjectKey{Name: deployName, Namespace: topo.Namespace}, deploy); err == nil {
			readyNodes += deploy.Status.ReadyReplicas
		}
	}

	// Determine phase
	phase := "Pending"
	if readyNodes == totalNodes && totalNodes > 0 {
		phase = "Running"
	} else if readyNodes > 0 {
		phase = "Running" // Partially running
	}

	// Update status if changed
	needsUpdate := false
	if topo.Status.NodeCount != int(totalNodes) {
		topo.Status.NodeCount = int(totalNodes)
		needsUpdate = true
	}
	if topo.Status.ReadyNodes != int(readyNodes) {
		topo.Status.ReadyNodes = int(readyNodes)
		needsUpdate = true
	}
	if topo.Status.Phase != phase {
		topo.Status.Phase = phase
		needsUpdate = true
	}

	if needsUpdate {
		return r.Status().Update(ctx, topo)
	}
	return nil
}
