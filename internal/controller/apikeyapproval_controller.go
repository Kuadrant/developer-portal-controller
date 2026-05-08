/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"

	"github.com/samber/lo"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	devportalv1alpha1 "github.com/kuadrant/developer-portal-controller/api/v1alpha1"
)

// APIKeyApprovalReconciler reconciles APIKeyApproval lifecycle (owner references)
type APIKeyApprovalReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apikeyapprovals,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apikeyrequests,verbs=get;list;watch

// Reconcile handles reconciling all APIKeyApprovals in a single call. Any resource event should enqueue the
// same reconcile.Request containing this controller name, i.e. "apikeyapproval". This allows multiple resource updates to
// be handled by a single call to Reconcile. The reconcile.Request DOES NOT map to a specific resource.
func (r *APIKeyApprovalReconciler) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)

	logger.V(1).Info("reconciling apikeyapproval")
	defer logger.V(1).Info("reconciling apikeyapproval: done")

	apiKeyApprovalList := &devportalv1alpha1.APIKeyApprovalList{}
	err := r.List(ctx, apiKeyApprovalList)
	if err != nil {
		return ctrl.Result{}, err
	}

	apiKeyRequestList := &devportalv1alpha1.APIKeyRequestList{}
	err = r.List(ctx, apiKeyRequestList)
	if err != nil {
		return ctrl.Result{}, err
	}

	ctx = WithAPIKeyRequests(ctx, apiKeyRequestList)

	// filter out flagged for deletion
	activeAPIKeyApprovalList := lo.Filter(apiKeyApprovalList.Items, func(approval devportalv1alpha1.APIKeyApproval, _ int) bool {
		return approval.GetDeletionTimestamp() == nil
	})

	for idx := range activeAPIKeyApprovalList {
		err := r.reconcileOwnerReference(ctx, &activeAPIKeyApprovalList[idx])
		if err != nil {
			if apierrors.IsConflict(err) {
				// Ignore conflicts, resource might just be outdated.
				logger.Info("failed to set owner reference: resource might just be outdated", "apikeyapproval", client.ObjectKeyFromObject(&activeAPIKeyApprovalList[idx]))
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *APIKeyApprovalReconciler) reconcileOwnerReference(ctx context.Context, approval *devportalv1alpha1.APIKeyApproval) error {
	logger := logf.FromContext(ctx, "apikeyapproval", client.ObjectKeyFromObject(approval))

	// Get APIKeyRequests from context
	apiKeyRequests := GetAPIKeyRequests(ctx)
	if apiKeyRequests == nil {
		apiKeyRequests = &devportalv1alpha1.APIKeyRequestList{}
	}

	// Find the referenced APIKeyRequest in the same namespace
	var foundRequest *devportalv1alpha1.APIKeyRequest
	for i := range apiKeyRequests.Items {
		if apiKeyRequests.Items[i].Namespace == approval.Namespace &&
			apiKeyRequests.Items[i].Name == approval.Spec.APIKeyRequestRef.Name {
			foundRequest = &apiKeyRequests.Items[i]
			break
		}
	}

	// APIKeyRequest not found or being deleted - skip setting owner reference
	if foundRequest == nil || foundRequest.GetDeletionTimestamp() != nil {
		return nil
	}

	// Check if owner reference is already set
	for _, ownerRef := range approval.OwnerReferences {
		if ownerRef.UID == foundRequest.UID {
			// Owner reference already set
			return nil
		}
	}

	// Set APIKeyRequest as owner of APIKeyApproval for automatic garbage collection
	if err := controllerutil.SetControllerReference(foundRequest, approval, r.Scheme); err != nil {
		logger.Error(err, "Failed to set owner reference on APIKeyApproval")
		return err
	}

	// Update the APIKeyApproval with the owner reference
	if err := r.Update(ctx, approval); err != nil {
		logger.Error(err, "Failed to update APIKeyApproval with owner reference")
		return err
	}

	logger.Info("Set owner reference to APIKeyRequest")
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *APIKeyApprovalReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Watches(&devportalv1alpha1.APIKeyApproval{}, handler.EnqueueRequestsFromMapFunc(r.enqueueClass)).
		Watches(&devportalv1alpha1.APIKeyRequest{}, handler.EnqueueRequestsFromMapFunc(r.enqueueClass)).
		Named("apikeyapproval").
		Complete(r)
}

func (r *APIKeyApprovalReconciler) enqueueClass(_ context.Context, _ client.Object) []ctrl.Request {
	return []ctrl.Request{{NamespacedName: types.NamespacedName{
		Name: string("apikeyapproval"),
	}}}
}
