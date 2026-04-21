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
	corev1 "k8s.io/api/core/v1"
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
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	authorinov1beta3 "github.com/kuadrant/authorino/api/v1beta3"
	kuadrantapiv1 "github.com/kuadrant/kuadrant-operator/api/v1"
	planpolicyv1alpha1 "github.com/kuadrant/kuadrant-operator/cmd/extensions/plan-policy/api/v1alpha1"

	devportalv1alpha1 "github.com/kuadrant/developer-portal-controller/api/v1alpha1"
)

// APIProductReconciler reconciles a APIProduct object
type APIKeyStatusReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apikeys,verbs=get;list;watch
// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apikeys/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apiproducts,verbs=get;list;watch
// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apikeyapprovals,verbs=get;list;watch
// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apikeyrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes,verbs=get;list;watch

// Reconcile handles reconciling all resources in a single call. Any resource event should enqueue the
// same reconcile.Request containing this controller name, i.e. "apikey-status". This allows multiple resource updates to
// be handled by a single call to Reconcile. The reconcile.Request DOES NOT map to a specific resource.
func (r *APIKeyStatusReconciler) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)

	logger.V(1).Info("reconciling apikey status")
	defer logger.V(1).Info("reconciling apikey status: done")

	apiKeyList := &devportalv1alpha1.APIKeyList{}
	err := r.List(ctx, apiKeyList)
	if err != nil {
		return ctrl.Result{}, err
	}

	ctx = WithAPIKeys(ctx, apiKeyList)

	apiKeyRequestList := &devportalv1alpha1.APIKeyRequestList{}
	err = r.List(ctx, apiKeyRequestList)
	if err != nil {
		return ctrl.Result{}, err
	}

	ctx = WithAPIKeyRequests(ctx, apiKeyRequestList)

	apiKeyApprovalList := &devportalv1alpha1.APIKeyApprovalList{}
	err = r.List(ctx, apiKeyApprovalList)
	if err != nil {
		return ctrl.Result{}, err
	}

	ctx = WithAPIKeyApprovals(ctx, apiKeyApprovalList)

	// filter out flagged for deletion
	activeAPIKeyList := lo.Filter(apiKeyList.Items, func(api devportalv1alpha1.APIKey, _ int) bool {
		return api.GetDeletionTimestamp() == nil
	})

	for idx := range activeAPIKeyList {
		err := r.reconcileStatus(ctx, &activeAPIKeyList[idx])
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

func (r *APIKeyStatusReconciler) reconcileStatus(ctx context.Context, apiKey *devportalv1alpha1.APIKey) error {
	logger := logf.FromContext(ctx, "apikey", client.ObjectKeyFromObject(apiKey))

	newStatus, err := r.calculateStatus(ctx, apiKey)
	if err != nil {
		return err
	}

	equalStatus := equality.Semantic.DeepEqual(newStatus, &apiKey.Status)
	if equalStatus && apiKey.Generation == apiKey.Status.ObservedGeneration {
		logger.V(1).Info("apiproduct status unchanged, skipping update")
		return nil
	}
	apiKey.Status = *newStatus

	updateErr := r.Status().Update(ctx, apiKey)
	if updateErr != nil {
		return updateErr
	}

	logger.Info("status updated")

	return nil
}

func (r *APIKeyStatusReconciler) calculateStatus(ctx context.Context, apiKey *devportalv1alpha1.APIKey) (*devportalv1alpha1.APIKeyStatus, error) {
	newStatus := &devportalv1alpha1.APIKeyStatus{
		ObservedGeneration: apiKey.Generation,
	}

	newConditions, err := r.calculateStatusConditions(ctx, apiKey)
	if err != nil {
		return nil, err
	}

	newStatus.Conditions = newConditions

	authScheme, err := r.calculateAuthScheme(ctx, apiKey)
	if err != nil {
		return nil, err
	}
	newStatus.AuthScheme = authScheme

	planLimits, err := r.calculatePlanLimits(ctx, apiKey)
	if err != nil {
		return nil, err
	}
	newStatus.Limits = planLimits

	apiHostName, err := r.apiHostName(ctx, apiKey)
	if err != nil {
		return nil, err
	}
	newStatus.APIHostname = apiHostName

	// No active condition - pending state (empty conditions)
	return newStatus, nil
}

func (r *APIKeyStatusReconciler) calculateStatusConditions(ctx context.Context, apiKey *devportalv1alpha1.APIKey) ([]metav1.Condition, error) {
	conditions := slices.Clone(apiKey.Status.Conditions)

	// Check Failed condition first - if failed, we're done
	failedCondition, err := r.calculateFailedCondition(ctx, apiKey)
	if err != nil {
		return nil, err
	}
	if failedCondition != nil {
		meta.RemoveStatusCondition(&conditions, devportalv1alpha1.APIKeyConditionApproved)
		meta.RemoveStatusCondition(&conditions, devportalv1alpha1.APIKeyConditionDenied)
		meta.SetStatusCondition(&conditions, *failedCondition)
		meta.SetStatusCondition(&conditions, *failedCondition)
		return conditions, nil
	}

	// Check for Denied condition - if denied, we're done
	deniedCondition := r.calculateDeniedCondition(ctx, apiKey)
	if deniedCondition != nil {
		meta.RemoveStatusCondition(&conditions, devportalv1alpha1.APIKeyConditionApproved)
		meta.RemoveStatusCondition(&conditions, devportalv1alpha1.APIKeyConditionFailed)
		meta.SetStatusCondition(&conditions, *deniedCondition)
		return conditions, nil
	}

	// Check for Approved condition - if approved, we're done
	approvedCondition := r.calculateApprovedCondition(ctx, apiKey)
	if approvedCondition != nil {
		meta.RemoveStatusCondition(&conditions, devportalv1alpha1.APIKeyConditionDenied)
		meta.RemoveStatusCondition(&conditions, devportalv1alpha1.APIKeyConditionFailed)
		meta.SetStatusCondition(&conditions, *approvedCondition)
		return conditions, nil
	}

	return conditions, nil
}

func (r *APIKeyStatusReconciler) calculateFailedCondition(ctx context.Context, apiKey *devportalv1alpha1.APIKey) (*metav1.Condition, error) {
	// Check if the referenced APIProduct exists
	apiProduct := &devportalv1alpha1.APIProduct{}
	apiProductKey := apiKey.APIProductKey()

	err := r.Get(ctx, apiProductKey, apiProduct)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return &metav1.Condition{
				Type:               devportalv1alpha1.APIKeyConditionFailed,
				Status:             metav1.ConditionTrue,
				ObservedGeneration: apiKey.Generation,
				Reason:             "APIProductNotFound",
				Message:            fmt.Sprintf("Referenced APIProduct %s not found", apiProductKey),
			}, nil
		}
		// Return the error for other types of errors (network issues, etc.)
		return nil, err
	}

	// Check if APIProduct is being deleted
	if apiProduct.GetDeletionTimestamp() != nil {
		return &metav1.Condition{
			Type:               devportalv1alpha1.APIKeyConditionFailed,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: apiKey.Generation,
			Reason:             "APIProductDeleting",
			Message:            fmt.Sprintf("Referenced APIProduct %s is being deleted", apiProductKey),
		}, nil
	}

	// Check if the referenced Secret exists
	// Skip validation if SecretRef.Name is empty (should be caught by validation, but be defensive)
	if apiKey.Spec.SecretRef.Name == "" {
		// This should not happen due to kubebuilder validation, but handle gracefully
		return nil, nil
	}

	secret := &corev1.Secret{}
	secretKey := client.ObjectKey{
		Namespace: apiKey.Namespace,
		Name:      apiKey.Spec.SecretRef.Name,
	}

	err = r.Get(ctx, secretKey, secret)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return &metav1.Condition{
				Type:               devportalv1alpha1.APIKeyConditionFailed,
				Status:             metav1.ConditionTrue,
				ObservedGeneration: apiKey.Generation,
				Reason:             "SecretNotFound",
				Message:            fmt.Sprintf("Referenced secret %s not found", secretKey),
			}, nil
		}
		// Return the error for other types of errors (network issues, etc.)
		return nil, err
	}

	// Check if the secret has the api_key entry
	if _, ok := secret.Data[apiKeySecretKey]; !ok {
		return &metav1.Condition{
			Type:               devportalv1alpha1.APIKeyConditionFailed,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: apiKey.Generation,
			Reason:             "SecretAPIKeyNotFound",
			Message:            fmt.Sprintf("Secret %s does not contain %q entry", secretKey, apiKeySecretKey),
		}, nil
	}

	// No failure detected
	return nil, nil
}

func (r *APIKeyStatusReconciler) calculateDeniedCondition(ctx context.Context, apiKey *devportalv1alpha1.APIKey) *metav1.Condition {
	approval := r.findAPIKeyApproval(ctx, apiKey)

	if approval != nil && !approval.Spec.Approved {
		message := fmt.Sprintf("API key request denied by %s", approval.Spec.ReviewedBy)
		if approval.Spec.Reason != "" {
			message = fmt.Sprintf("%s: %s", message, approval.Spec.Reason)
		}
		return &metav1.Condition{
			Type:               devportalv1alpha1.APIKeyConditionDenied,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: apiKey.Generation,
			Reason:             "Denied",
			Message:            message,
		}
	}

	return nil
}

func (r *APIKeyStatusReconciler) calculateApprovedCondition(ctx context.Context, apiKey *devportalv1alpha1.APIKey) *metav1.Condition {
	approval := r.findAPIKeyApproval(ctx, apiKey)

	if approval != nil && approval.Spec.Approved {
		message := fmt.Sprintf("API key request approved by %s", approval.Spec.ReviewedBy)
		if approval.Spec.Message != "" {
			message = fmt.Sprintf("%s: %s", message, approval.Spec.Message)
		}
		return &metav1.Condition{
			Type:               devportalv1alpha1.APIKeyConditionApproved,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: apiKey.Generation,
			Reason:             "Approved",
			Message:            message,
		}
	}

	return nil
}

func (r *APIKeyStatusReconciler) findAPIKeyApproval(ctx context.Context, apiKey *devportalv1alpha1.APIKey) *devportalv1alpha1.APIKeyApproval {
	logger := logf.FromContext(ctx)

	// Determine the APIProduct namespace
	apiProductKey := apiKey.APIProductKey()

	// Construct the APIKeyRequest name that corresponds to this APIKey
	apiKeyRequestName := APIKeyRequestName(apiKey)

	// Get APIKeyApprovals from context
	apiKeyApprovals := GetAPIKeyApprovals(ctx)
	if apiKeyApprovals == nil {
		apiKeyApprovals = &devportalv1alpha1.APIKeyApprovalList{}
	}

	// Filter out invalid APIKeyApprovals
	validApprovals := lo.Filter(apiKeyApprovals.Items, func(approval devportalv1alpha1.APIKeyApproval, _ int) bool {
		validCondition := meta.FindStatusCondition(approval.Status.Conditions, devportalv1alpha1.APIKeyApprovalConditionValid)
		if validCondition == nil || validCondition.Status != metav1.ConditionTrue {
			logger.V(1).Info("filtering out invalid apikeyapproval",
				"apikeyapproval", client.ObjectKeyFromObject(&approval),
				"reason", getInvalidReason(validCondition))
			return false
		}
		return true
	})

	// Find the APIKeyApproval that references our APIKeyRequest
	for i := range validApprovals {
		if validApprovals[i].Namespace == apiProductKey.Namespace &&
			validApprovals[i].Spec.APIKeyRequestRef.Name == apiKeyRequestName {
			return &validApprovals[i]
		}
	}

	return nil
}

func getInvalidReason(validCondition *metav1.Condition) string {
	if validCondition == nil {
		return "Valid condition not set"
	}
	return validCondition.Reason
}

func (r *APIKeyStatusReconciler) calculateAuthScheme(ctx context.Context, apiKey *devportalv1alpha1.APIKey) (*devportalv1alpha1.AuthScheme, error) {
	logger := logf.FromContext(ctx)

	apiProduct, err := r.getAPIProduct(ctx, apiKey)
	if err != nil {
		return nil, err
	}
	if apiProduct == nil {
		return nil, nil
	}
	if apiProduct.Status.DiscoveredAuthScheme == nil {
		logger.V(1).Info("Referenced APIProduct from APIKey lacks discovered auth scheme", "apiKey", client.ObjectKeyFromObject(apiKey))
		return nil, nil
	}

	apiKeyAuthMethods := lo.FilterValues(apiProduct.Status.DiscoveredAuthScheme.Authentication, func(k string, v kuadrantapiv1.MergeableAuthenticationSpec) bool {
		return v.GetMethod() == authorinov1beta3.ApiKeyAuthentication
	})

	if len(apiKeyAuthMethods) > 0 {
		return &devportalv1alpha1.AuthScheme{
			AuthenticationSpec: apiKeyAuthMethods[0].ApiKey, // TODO: Decide the heuristics about targeting specific APIKey(s), picking the first one for now.
			Credentials:        &apiKeyAuthMethods[0].Credentials,
		}, nil
	}

	return nil, nil
}

func (r *APIKeyStatusReconciler) getAPIProduct(ctx context.Context, apiKey *devportalv1alpha1.APIKey) (*devportalv1alpha1.APIProduct, error) {
	logger := logf.FromContext(ctx)

	apiProduct := &devportalv1alpha1.APIProduct{}
	apiProductKey := apiKey.APIProductKey()

	if err := r.Get(ctx, apiProductKey, apiProduct); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(1).Info("Referenced APIProduct not found", "apiProduct", apiProductKey)
			return nil, nil
		}
		return nil, err
	}
	return apiProduct, nil
}

func (r *APIKeyStatusReconciler) apiHostName(ctx context.Context, apiKey *devportalv1alpha1.APIKey) (string, error) {
	logger := logf.FromContext(ctx)

	// Get the APIProduct
	apiProduct, err := r.getAPIProduct(ctx, apiKey)
	if err != nil {
		return "", err
	}
	if apiProduct == nil {
		logger.V(1).Info("Referenced APIProduct not found, cannot determine hostname")
		return "", nil
	}

	// Get the HTTPRoute referenced by the APIProduct
	route := &gwapiv1.HTTPRoute{}
	routeKey := client.ObjectKey{
		Namespace: apiProduct.Namespace,
		Name:      string(apiProduct.Spec.TargetRef.Name),
	}

	err = r.Get(ctx, routeKey, route)
	if err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(1).Info("HTTPRoute not found, cannot determine hostname", "httpRoute", routeKey)
			return "", nil
		}
		return "", err
	}

	// Extract the first hostname from the HTTPRoute
	if len(route.Spec.Hostnames) > 0 {
		return string(route.Spec.Hostnames[0]), nil
	}

	logger.V(1).Info("HTTPRoute has no hostnames defined", "httpRoute", routeKey)
	return "", nil
}

func (r *APIKeyStatusReconciler) calculatePlanLimits(ctx context.Context, apiKey *devportalv1alpha1.APIKey) (*planpolicyv1alpha1.Limits, error) {
	apiProduct, err := r.getAPIProduct(ctx, apiKey)
	if err != nil {
		return nil, err
	}
	if apiProduct == nil {
		return nil, nil
	}

	for _, plan := range apiProduct.Status.DiscoveredPlans {
		if plan.Tier == apiKey.Spec.PlanTier {
			return &plan.Limits, nil
		}
	}
	return nil, nil
}

// Clear all status condition types (Approved, Denied, Failed)

// SetupWithManager sets up the controller with the Manager.
func (r *APIKeyStatusReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Watches(&devportalv1alpha1.APIKey{}, handler.EnqueueRequestsFromMapFunc(r.enqueueClass)).
		Watches(&devportalv1alpha1.APIProduct{}, handler.EnqueueRequestsFromMapFunc(r.enqueueClass)).
		Watches(&devportalv1alpha1.APIKeyRequest{}, handler.EnqueueRequestsFromMapFunc(r.enqueueClass)).
		Watches(&devportalv1alpha1.APIKeyApproval{}, handler.EnqueueRequestsFromMapFunc(r.enqueueClass)).
		Watches(&gwapiv1.HTTPRoute{}, handler.EnqueueRequestsFromMapFunc(r.enqueueClass)).
		Named("apikey-status").
		Complete(r)
}

func (r *APIKeyStatusReconciler) enqueueClass(_ context.Context, _ client.Object) []ctrl.Request {
	return []ctrl.Request{{NamespacedName: types.NamespacedName{
		Name: string("apikey-status"),
	}}}
}
