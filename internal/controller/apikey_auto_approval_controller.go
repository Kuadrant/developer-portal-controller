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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	devportalv1alpha1 "github.com/kuadrant/developer-portal-controller/api/v1alpha1"
)

// APIKeyAutoApprovalReconciler automatically creates APIKeyApproval resources
// for APIKeyRequests targeting APIProducts with automatic approval mode
type APIKeyAutoApprovalReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apikeyrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apikeyapprovals,verbs=get;list;create
// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apiproducts,verbs=get;list

func (r *APIKeyAutoApprovalReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx, "apikeyrequest", req.NamespacedName)
	logger.V(1).Info("reconciling apikey auto approval")
	defer logger.V(1).Info("reconciling apikey auto approval: done")

	// Get APIKeyRequest object
	apiKeyRequest := &devportalv1alpha1.APIKeyRequest{}
	if err := r.Get(ctx, req.NamespacedName, apiKeyRequest); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("no object found")
			return ctrl.Result{}, nil
		}

		logger.Error(err, "Failed to get apikeyrequest object.")
		return ctrl.Result{}, err
	}

	if apiKeyRequest.GetDeletionTimestamp() != nil {
		return ctrl.Result{}, nil
	}

	// 1. Check if APIKeyRequest has Pending condition with status=True
	// If status hasn't been set yet, we proceed anyway (defensive programming)
	pendingCondition := meta.FindStatusCondition(apiKeyRequest.Status.Conditions, devportalv1alpha1.APIKeyConditionPending)

	// Skip if not pending (either approved, denied, or other state)
	if pendingCondition == nil || pendingCondition.Status != metav1.ConditionTrue {
		logger.V(1).Info("APIKeyRequest is not in pending state, skipping auto-approval")
		return ctrl.Result{}, nil
	}

	// 2. Fetch the referenced APIProduct
	product := &devportalv1alpha1.APIProduct{}
	productKey := client.ObjectKey{
		Namespace: apiKeyRequest.Namespace,
		Name:      apiKeyRequest.Spec.APIProductRef.Name,
	}
	if err := r.Get(ctx, productKey, product); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(1).Info("referenced APIProduct not found")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// 3. Check if APIProduct is being deleted
	if product.GetDeletionTimestamp() != nil {
		logger.V(1).Info("APIProduct is being deleted, skipping auto-approval")
		return ctrl.Result{}, nil
	}

	// 4. Check if approval mode is automatic
	if product.Spec.ApprovalMode != "automatic" {
		logger.V(1).Info("APIProduct approval mode is not automatic", "mode", product.Spec.ApprovalMode)
		return ctrl.Result{}, nil
	}

	// 5. Check if any APIKeyApproval already exists for this request
	// Address race conditions when apikey is still pending but an apikeyapproval resource already exists.
	approvalList := &devportalv1alpha1.APIKeyApprovalList{}
	if err := r.List(ctx, approvalList, client.InNamespace(apiKeyRequest.Namespace)); err != nil {
		return ctrl.Result{}, err
	}

	for _, approval := range approvalList.Items {
		if approval.Spec.APIKeyRequestRef.Name == apiKeyRequest.Name {
			logger.V(1).Info("APIKeyApproval already exists for this request, skipping auto-approval",
				"approval", approval.Name)
			return ctrl.Result{}, nil
		}
	}

	// 6. Create auto-approval
	approval := &devportalv1alpha1.APIKeyApproval{
		ObjectMeta: metav1.ObjectMeta{
			Name:      apiKeyRequest.Name + "-auto",
			Namespace: apiKeyRequest.Namespace,
		},
		Spec: devportalv1alpha1.APIKeyApprovalSpec{
			APIKeyRequestRef: devportalv1alpha1.APIKeyRequestReference{
				Name: apiKeyRequest.Name,
			},
			Approved:   true,
			ReviewedBy: "system",
			ReviewedAt: metav1.Now(),
			Reason:     "AutoApproved",
			Message:    "Automatically approved based on APIProduct approval mode",
		},
	}

	logger.Info("creating automatic approval")
	err := r.Create(ctx, approval)
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Approval already created (race condition or duplicate), skip
			logger.V(1).Info("auto-approval already exists", "apikeyrequest", client.ObjectKeyFromObject(apiKeyRequest))
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *APIKeyAutoApprovalReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&devportalv1alpha1.APIKeyRequest{}).
		Named("apikeyrequest-autoapproval").
		Complete(r)
}
