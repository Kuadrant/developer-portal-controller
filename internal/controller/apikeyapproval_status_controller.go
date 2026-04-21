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
	"fmt"
	"slices"

	"github.com/samber/lo"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	devportalv1alpha1 "github.com/kuadrant/developer-portal-controller/api/v1alpha1"
)

// APIKeyApprovalStatusReconciler reconciles APIKeyApproval status
type APIKeyApprovalStatusReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apikeyapprovals,verbs=get;list;watch
// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apikeyapprovals/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apikeyrequests,verbs=get;list;watch

// Reconcile handles reconciling all APIKeyApprovals in a single call. Any resource event should enqueue the
// same reconcile.Request containing this controller name, i.e. "apikeyapproval-status". This allows multiple resource updates to
// be handled by a single call to Reconcile. The reconcile.Request DOES NOT map to a specific resource.
func (r *APIKeyApprovalStatusReconciler) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)

	logger.V(1).Info("reconciling apikeyapproval status")
	defer logger.V(1).Info("reconciling apikeyapproval status: done")

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
		err := r.reconcileStatus(ctx, &activeAPIKeyApprovalList[idx])
		if err != nil {
			if apierrors.IsConflict(err) {
				// Ignore conflicts, resource might just be outdated.
				logger.Info("failed to update status: resource might just be outdated")
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *APIKeyApprovalStatusReconciler) reconcileStatus(ctx context.Context, approval *devportalv1alpha1.APIKeyApproval) error {
	logger := logf.FromContext(ctx, "apikeyapproval", client.ObjectKeyFromObject(approval))

	newStatus := r.calculateStatus(ctx, approval)
	equalStatus := equality.Semantic.DeepEqual(newStatus, &approval.Status)
	if equalStatus && approval.Generation == approval.Status.ObservedGeneration {
		logger.V(1).Info("apikeyapproval status unchanged, skipping update")
		return nil
	}
	approval.Status = *newStatus

	updateErr := r.Status().Update(ctx, approval)
	if updateErr != nil {
		return updateErr
	}

	logger.Info("status updated")

	return nil
}

func (r *APIKeyApprovalStatusReconciler) calculateStatus(ctx context.Context, approval *devportalv1alpha1.APIKeyApproval) *devportalv1alpha1.APIKeyApprovalStatus {
	newStatus := &devportalv1alpha1.APIKeyApprovalStatus{
		ObservedGeneration: approval.Generation,
		// Copy initial conditions. Otherwise, status will always be updated
		Conditions: slices.Clone(approval.Status.Conditions),
	}

	// Calculate Valid condition
	validCondition := r.calculateValidCondition(ctx, approval)
	if validCondition != nil {
		meta.SetStatusCondition(&newStatus.Conditions, *validCondition)
	}

	return newStatus
}

func (r *APIKeyApprovalStatusReconciler) calculateValidCondition(ctx context.Context, approval *devportalv1alpha1.APIKeyApproval) *metav1.Condition {
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

	// APIKeyRequest not found
	if foundRequest == nil {
		return &metav1.Condition{
			Type:               devportalv1alpha1.APIKeyApprovalConditionValid,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: approval.Generation,
			Reason:             "APIKeyRequestNotFound",
			Message:            fmt.Sprintf("Referenced APIKeyRequest %s/%s not found", approval.Namespace, approval.Spec.APIKeyRequestRef.Name),
		}
	}

	// Check if APIKeyRequest is being deleted
	if foundRequest.GetDeletionTimestamp() != nil {
		return &metav1.Condition{
			Type:               devportalv1alpha1.APIKeyApprovalConditionValid,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: approval.Generation,
			Reason:             "APIKeyRequestDeleting",
			Message:            fmt.Sprintf("Referenced APIKeyRequest %s/%s is being deleted", approval.Namespace, approval.Spec.APIKeyRequestRef.Name),
		}
	}

	// Valid - APIKeyRequest exists and is not being deleted
	return &metav1.Condition{
		Type:               devportalv1alpha1.APIKeyApprovalConditionValid,
		Status:             metav1.ConditionTrue,
		ObservedGeneration: approval.Generation,
		Reason:             "Valid",
		Message:            fmt.Sprintf("References existing APIKeyRequest %s/%s", approval.Namespace, approval.Spec.APIKeyRequestRef.Name),
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *APIKeyApprovalStatusReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Watches(&devportalv1alpha1.APIKeyApproval{}, handler.EnqueueRequestsFromMapFunc(r.enqueueClass)).
		Watches(&devportalv1alpha1.APIKeyRequest{}, handler.EnqueueRequestsFromMapFunc(r.enqueueClass)).
		Named("apikeyapproval-status").
		Complete(r)
}

func (r *APIKeyApprovalStatusReconciler) enqueueClass(_ context.Context, _ client.Object) []ctrl.Request {
	return []ctrl.Request{{NamespacedName: types.NamespacedName{
		Name: string("apikeyapproval-status"),
	}}}
}
