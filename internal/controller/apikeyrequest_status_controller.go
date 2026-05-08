/*
Copyright 2025.

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	devportalv1alpha1 "github.com/kuadrant/developer-portal-controller/api/v1alpha1"
)

// APIKeyRequestReconciler reconciles APIKey objects to create shadow APIKeyRequest resources
type APIKeyRequestStatusReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apikeys,verbs=get;list;watch
// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apikeyrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apikeyrequests/status,verbs=get;update;patch

func (r *APIKeyRequestStatusReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// List all APIKeyRequests cluster-wide
	apiKeyRequestList := &devportalv1alpha1.APIKeyRequestList{}
	if err := r.List(ctx, apiKeyRequestList); err != nil {
		logger.Error(err, "Failed to list APIKeyRequests")
		return ctrl.Result{}, err
	}

	// Process each APIKeyRequest
	for i := range apiKeyRequestList.Items {
		apiKeyRequest := &apiKeyRequestList.Items[i]
		apiKeyKey := apiKeyRequest.Spec.APIKeyRef.ClientObject()
		apiKey := &devportalv1alpha1.APIKey{}
		if err := r.Get(ctx, apiKeyKey, apiKey); err != nil {
			if apierrors.IsNotFound(err) {
				logger.V(1).Info("APIKey resource not found", "apikey", apiKeyKey)
				continue
			}
			logger.Error(err, "Failed to get APIKey")
			return ctrl.Result{}, err
		}

		// Skip APIKey that are being deleted
		if apiKey.DeletionTimestamp != nil {
			logger.V(1).Info("skipping APIKey marked for deletion", "apiKey", apiKeyKey)
			continue
		}

		// Sync status conditions from APIKey to APIKeyRequest
		if !conditionsEqual(apiKey.Status.Conditions, apiKeyRequest.Status.Conditions) {
			logger.V(1).Info("conditions not equal", "apiKeyKey", apiKeyKey)
			// Copy conditions from APIKey to APIKeyRequest
			apiKeyRequest.Status.Conditions = copyConditions(apiKey.Status.Conditions)
			if err := r.Status().Update(ctx, apiKeyRequest); err != nil {
				logger.Error(err, "Failed to update APIKeyRequest status", "apiKeyRequest", client.ObjectKeyFromObject(apiKeyRequest))
				return ctrl.Result{}, err
			}
			logger.Info("Synced status from APIKey to APIKeyRequest", "apiKeyRequest", client.ObjectKeyFromObject(apiKeyRequest))
		}
	}

	return ctrl.Result{}, nil
}

// conditionsEqual checks if two condition slices are equal
func conditionsEqual(a, b []metav1.Condition) bool {
	if len(a) != len(b) {
		return false
	}

	// Create maps for comparison
	aMap := make(map[string]metav1.Condition)
	for _, cond := range a {
		aMap[cond.Type] = cond
	}

	for _, condB := range b {
		condA, exists := aMap[condB.Type]
		if !exists {
			return false
		}
		if condA.Status != condB.Status ||
			condA.Reason != condB.Reason ||
			condA.Message != condB.Message ||
			condA.ObservedGeneration != condB.ObservedGeneration {
			return false
		}
	}

	return true
}

// copyConditions creates a deep copy of conditions
func copyConditions(conditions []metav1.Condition) []metav1.Condition {
	if conditions == nil {
		return nil
	}

	result := make([]metav1.Condition, len(conditions))
	for i, cond := range conditions {
		result[i] = metav1.Condition{
			Type:               cond.Type,
			Status:             cond.Status,
			ObservedGeneration: cond.ObservedGeneration,
			LastTransitionTime: cond.LastTransitionTime,
			Reason:             cond.Reason,
			Message:            cond.Message,
		}
	}
	return result
}

// SetupWithManager sets up the controller with the Manager.
func (r *APIKeyRequestStatusReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Watches(&devportalv1alpha1.APIProduct{}, handler.EnqueueRequestsFromMapFunc(r.enqueueClass)).
		Watches(&devportalv1alpha1.APIKey{}, handler.EnqueueRequestsFromMapFunc(r.enqueueClass)).
		Named("apikeyrequeststatus").
		Complete(r)
}

func (r *APIKeyRequestStatusReconciler) enqueueClass(_ context.Context, _ client.Object) []ctrl.Request {
	return []ctrl.Request{{NamespacedName: types.NamespacedName{
		Name: string("apikeyrequeststatus"),
	}}}
}
