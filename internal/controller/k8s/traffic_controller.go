package k8s

import (
	"context"

	kurov1alpha1 "kuro/api/crd/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
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

	if !tc.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
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

// SetupWithManager sets up the controller with the Manager.
func (r *TrafficControlReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// GenerationChangedPredicate ensures Reconcile is only triggered when the Spec (Generation) changes.
	// Any Status updates will be intercepted by this Predicate, preventing infinite loops.
	return ctrl.NewControllerManagedBy(mgr).
		For(&kurov1alpha1.TrafficControl{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}
