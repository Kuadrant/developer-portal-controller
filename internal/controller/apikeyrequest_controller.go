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
	"fmt"
	"reflect"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	devportalv1alpha1 "github.com/kuadrant/developer-portal-controller/api/v1alpha1"
	"github.com/kuadrant/developer-portal-controller/internal/reconcilers"
)

// APIKeyRequestReconciler reconciles APIKey objects to create shadow APIKeyRequest resources
type APIKeyRequestReconciler struct {
	reconcilers.BaseReconciler
}

// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apikeys,verbs=get;list;watch
// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apikeyrequests,verbs=get;list;watch;create;update;patch;delete

// Reconcile creates and manages shadow APIKeyRequest resources for all APIKey objects
func (r *APIKeyRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.V(1).Info("reconciling apikeyrequest", "status", "started")
	defer logger.V(1).Info("reconciling apikeyrequest", "status", "completed")

	// List all APIKeys cluster-wide
	apiKeyList := &devportalv1alpha1.APIKeyList{}
	if err := r.List(ctx, apiKeyList); err != nil {
		logger.Error(err, "Failed to list APIKeys")
		return ctrl.Result{}, err
	}

	// List all APIKeyRequests cluster-wide
	apiKeyRequestList := &devportalv1alpha1.APIKeyRequestList{}
	if err := r.List(ctx, apiKeyRequestList); err != nil {
		logger.Error(err, "Failed to list APIKeyRequests")
		return ctrl.Result{}, err
	}

	// Create a map of current APIKeys for cleanup check
	currentAPIKeys := make(map[client.ObjectKey]bool)

	// Process each APIKey
	for i := range apiKeyList.Items {
		apiKey := &apiKeyList.Items[i]
		apiKeyKey := client.ObjectKeyFromObject(apiKey)
		currentAPIKeys[apiKeyKey] = true

		// Check if APIKey is in Failed state
		failedCondition := meta.FindStatusCondition(apiKey.Status.Conditions, devportalv1alpha1.APIKeyConditionFailed)
		isFailedState := failedCondition != nil && failedCondition.Status == metav1.ConditionTrue

		apiProductNamespace := apiKey.Namespace
		if apiKey.Spec.APIProductRef.Namespace != "" {
			apiProductNamespace = apiKey.Spec.APIProductRef.Namespace
		}

		// Build the desired APIKeyRequest
		desiredRequest := &devportalv1alpha1.APIKeyRequest{
			ObjectMeta: metav1.ObjectMeta{
				// one to one mapping ensures no name conflict
				Name:      fmt.Sprintf("%s-%s", apiKey.Namespace, apiKey.Name),
				Namespace: apiProductNamespace,
			},
			Spec: devportalv1alpha1.APIKeyRequestSpec{
				APIProductRef: devportalv1alpha1.LocalAPIProductReference{
					Name: apiKey.Spec.APIProductRef.Name,
				},
				PlanTier:    apiKey.Spec.PlanTier,
				UseCase:     apiKey.Spec.UseCase,
				RequestedBy: apiKey.Spec.RequestedBy,
				APIKeyRef: devportalv1alpha1.APIKeyReference{
					Name:      apiKey.Name,
					Namespace: apiKey.Namespace,
				},
			},
		}

		// Mark shadow resource for deletion if APIKey is being deleted or in Failed state
		if apiKey.DeletionTimestamp != nil || isFailedState {
			reconcilers.TagObjectToDelete(desiredRequest)
		}

		mutator := reconcilers.Mutator(apiKeyRequestSpecMutator)
		_, err := r.ReconcileResource(ctx, &devportalv1alpha1.APIKeyRequest{}, desiredRequest, mutator)
		if err != nil {
			logger.Error(err, "Failed to reconcile APIKeyRequest", "apiKey", apiKeyKey)
			return ctrl.Result{}, err
		}

	}

	// Cleanup: Delete APIKeyRequests that no longer have corresponding APIKeys
	for i := range apiKeyRequestList.Items {
		request := &apiKeyRequestList.Items[i]
		apiKeyKey := client.ObjectKey{
			Namespace: request.Spec.APIKeyRef.Namespace,
			Name:      request.Spec.APIKeyRef.Name,
		}

		if !currentAPIKeys[apiKeyKey] {
			// The APIKey no longer exists, delete the APIKeyRequest
			if err := r.Delete(ctx, request); err != nil {
				if !apierrors.IsNotFound(err) {
					logger.Error(err, "Failed to delete orphaned APIKeyRequest", "apiKeyRequest", client.ObjectKeyFromObject(request))
					return ctrl.Result{}, err
				}
			} else {
				logger.Info("Deleted orphaned APIKeyRequest", "apiKeyRequest", client.ObjectKeyFromObject(request))
			}
		}
	}

	return ctrl.Result{}, nil
}

func apiKeyRequestSpecMutator(desired, existing *devportalv1alpha1.APIKeyRequest) bool {
	needsUpdate := false

	if !reflect.DeepEqual(existing.Spec, desired.Spec) {
		existing.Spec = desired.Spec
		needsUpdate = true
	}
	return needsUpdate
}

// SetupWithManager sets up the controller with the Manager.
func (r *APIKeyRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Watches(&devportalv1alpha1.APIProduct{}, handler.EnqueueRequestsFromMapFunc(r.enqueueClass)).
		Watches(&devportalv1alpha1.APIKey{}, handler.EnqueueRequestsFromMapFunc(r.enqueueClass)).
		Named("apikeyrequest").
		Complete(r)
}

func (r *APIKeyRequestReconciler) enqueueClass(_ context.Context, _ client.Object) []ctrl.Request {
	return []ctrl.Request{{NamespacedName: types.NamespacedName{
		Name: string("apikeyrequest"),
	}}}
}
