package k8s

import (
	"context"

	kurov1alpha1 "kuro/api/crd/v1alpha1"
	"kuro/internal/domain"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const (
	// trafficControlFinalizer is used to ensure cleanup of BPF rules before deletion
	trafficControlFinalizer = "simulation.kuro.io/cleanup"
)

// AgentCommander define interface of ControllerManager
type AgentCommander interface {
	SendCommand(nodeName string, refKey string, payload any) (string, error)
}

// TrafficControlReconciler reconciles a TrafficControl object
type TrafficControlReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	AgentManager AgentCommander
}

func (r *TrafficControlReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// 1. Fetch TrafficControl CRD
	var tc kurov1alpha1.TrafficControl
	if err := r.Get(ctx, req.NamespacedName, &tc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// 2. Handle Deletion with Finalizer Pattern
	if !tc.DeletionTimestamp.IsZero() {
		// The object is being deleted
		if controllerutil.ContainsFinalizer(&tc, trafficControlFinalizer) {
			// Run cleanup logic - delete BPF rules
			if err := r.cleanupTrafficControl(ctx, &tc); err != nil {
				logger.Error(err, "Failed to cleanup TrafficControl")
				return ctrl.Result{}, err
			}

			// Remove finalizer to allow deletion
			controllerutil.RemoveFinalizer(&tc, trafficControlFinalizer)
			if err := r.Update(ctx, &tc); err != nil {
				logger.Error(err, "Failed to remove finalizer")
				return ctrl.Result{}, err
			}
			logger.Info("TrafficControl cleanup completed, finalizer removed")
		}
		return ctrl.Result{}, nil
	}

	// 3. Add Finalizer if not present
	if !controllerutil.ContainsFinalizer(&tc, trafficControlFinalizer) {
		controllerutil.AddFinalizer(&tc, trafficControlFinalizer)
		if err := r.Update(ctx, &tc); err != nil {
			logger.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
		logger.Info("Added finalizer to TrafficControl")
	}

	// If the ObservedGeneration in Status already equals the current Generation,
	// it means this version of the Spec has already been processed; skip it.
	// Note: If you need to force-refresh rules periodically (e.g., every minute), remove this check.
	if tc.Status.ObservedGeneration == tc.Generation {
		logger.Info("Skipping reconcile: Spec not changed", "gen", tc.Generation)
		return ctrl.Result{}, nil
	}

	// 2. Parse Policy
	policyTemplate, err := ParseLinkPolicy(
		tc.Spec.Policy.Bandwidth,
		tc.Spec.Policy.Latency,
		tc.Spec.Policy.Jitter,
		tc.Spec.Policy.PacketLoss,
	)
	if err != nil {
		logger.Error(err, "Failed to parse policy")
		// Don't retry on user config error, update status to Failed if possible
		return ctrl.Result{}, nil
	}

	// 3. Find Source Pods
	srcSelector, _ := metav1.LabelSelectorAsSelector(&tc.Spec.Source)
	var srcPods corev1.PodList
	if err := r.List(ctx, &srcPods, client.InNamespace(req.Namespace), client.MatchingLabelsSelector{Selector: srcSelector}); err != nil {
		return ctrl.Result{}, err
	}

	// 4. Find Destination Pods
	dstSelector, _ := metav1.LabelSelectorAsSelector(&tc.Spec.Destination)
	var dstPods corev1.PodList
	if err := r.List(ctx, &dstPods, client.InNamespace(req.Namespace), client.MatchingLabelsSelector{Selector: dstSelector}); err != nil {
		return ctrl.Result{}, err
	}

	activeCount := 0

	// 5. Cartesian Product & Dispatch
	for _, src := range srcPods.Items {
		if src.Status.PodIP == "" || src.Spec.NodeName == "" {
			continue
		}

		// Clone policy for this specific link
		linkPolicy := policyTemplate
		linkPolicy.SrcIP = src.Status.PodIP

		for _, dst := range dstPods.Items {
			if dst.Status.PodIP == "" {
				continue
			}
			linkPolicy.DstIP = dst.Status.PodIP

			// Dispatch via gRPC
			// Target the Agent on the Source Node (Egress Control)
			_, err := r.AgentManager.SendCommand(src.Spec.NodeName, req.Name, linkPolicy)
			if err != nil {
				logger.Info("Failed to send command to agent", "node", src.Spec.NodeName, "err", err)
			} else {
				activeCount++
			}
		}
	}

	logger.Info("Reconciled TrafficControl", "name", tc.Name, "active_links", activeCount)
	return ctrl.Result{}, nil
}

// cleanupTrafficControl removes all BPF rules associated with this TrafficControl
// by sending delete commands to the agents for each (srcIP, dstIP) pair.
func (r *TrafficControlReconciler) cleanupTrafficControl(ctx context.Context, tc *kurov1alpha1.TrafficControl) error {
	logger := log.FromContext(ctx)
	logger.Info("Cleaning up TrafficControl BPF rules", "name", tc.Name)

	// 1. Find Source Pods
	srcSelector, _ := metav1.LabelSelectorAsSelector(&tc.Spec.Source)
	var srcPods corev1.PodList
	if err := r.List(ctx, &srcPods, client.InNamespace(tc.Namespace), client.MatchingLabelsSelector{Selector: srcSelector}); err != nil {
		logger.Error(err, "Failed to list source pods during cleanup")
		return err
	}

	// 2. Find Destination Pods
	dstSelector, _ := metav1.LabelSelectorAsSelector(&tc.Spec.Destination)
	var dstPods corev1.PodList
	if err := r.List(ctx, &dstPods, client.InNamespace(tc.Namespace), client.MatchingLabelsSelector{Selector: dstSelector}); err != nil {
		logger.Error(err, "Failed to list destination pods during cleanup")
		return err
	}

	deletedCount := 0

	// 3. Cartesian Product & Dispatch Delete Commands
	for _, src := range srcPods.Items {
		if src.Status.PodIP == "" || src.Spec.NodeName == "" {
			continue
		}

		for _, dst := range dstPods.Items {
			if dst.Status.PodIP == "" {
				continue
			}

			// Create delete policy
			deletePolicy := domain.LinkPolicy{
				SrcIP:    src.Status.PodIP,
				DstIP:    dst.Status.PodIP,
				IsDelete: true,
			}

			// Dispatch delete command via gRPC
			_, err := r.AgentManager.SendCommand(src.Spec.NodeName, tc.Name, deletePolicy)
			if err != nil {
				logger.Info("Failed to send delete command to agent", "node", src.Spec.NodeName, "err", err)
			} else {
				deletedCount++
			}
		}
	}

	logger.Info("TrafficControl cleanup completed", "name", tc.Name, "deleted_links", deletedCount)
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *TrafficControlReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// GenerationChangedPredicate ensures Reconcile is only triggered when the Spec (Generation) changes.
	// Any Status updates will be intercepted by this Predicate, preventing infinite loops.
	return ctrl.NewControllerManagedBy(mgr).
		For(&kurov1alpha1.TrafficControl{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}
