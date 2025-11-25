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
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	planpolicyv1alpha1 "github.com/kuadrant/kuadrant-operator/cmd/extensions/plan-policy/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	devportalv1alpha1 "github.com/kuadrant/developer-portal-controller/api/v1alpha1"
)

const (
	apiKeySecretAnnotationPlan      = "secret.kuadrant.io/plan-id"
	apiKeySecretAnnotationUser      = "secret.kuadrant.io/user-id"
	apiKeySecretLabelAuthorinoKey   = "authorino.kuadrant.io/managed-by"
	apiKeySecretLabelAuthorinoValue = "authorino"
	apiKeySecretKey                 = "api_key"
	apiKeyLength                    = 32 // bytes, will be base64 encoded
	apiKeyPhaseApproved             = "Approved"
	apiKeyPhasePending              = "Pending"
	apiKeyPhaseRejected             = "Rejected"
	apiKeyApprovalModeAutomatic     = "automatic"
)

// APIKeyReconciler reconciles a APIKey object
type APIKeyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apikeys,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apikeys/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apikeys/finalizers,verbs=update
// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apiproducts,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *APIKeyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the APIKey instance
	apiKey := &devportalv1alpha1.APIKey{}
	if err := r.Get(ctx, req.NamespacedName, apiKey); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("APIKey resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get APIKey")
		return ctrl.Result{}, err
	}
	// It'll be deleted
	if apiKey.GetDeletionTimestamp() != nil {
		logger.Info("APIKey marked to be deleted")
		return ctrl.Result{}, nil
	}

	// Initialize status if empty
	if apiKey.Status.Phase == "" {
		apiKey.Status.Phase = apiKeyPhasePending
	}

	// Process based on approval mode and current phase
	switch apiKey.Status.Phase {
	case apiKeyPhasePending:
		return r.reconcilePending(ctx, apiKey)
	case apiKeyPhaseApproved:
		return r.reconcileApproved(ctx, apiKey)
	case apiKeyPhaseRejected:
		return r.reconcileRejected(ctx, apiKey)
	}

	return ctrl.Result{}, nil
}

// reconcilePending handles APIKeys in the Pending phase.
func (r *APIKeyReconciler) reconcilePending(ctx context.Context, apiKey *devportalv1alpha1.APIKey) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Get APIProduct
	// Fetch the APIProduct to get additional metadata
	apiProduct := &devportalv1alpha1.APIProduct{}
	apiProductKey := types.NamespacedName{
		Name:      apiKey.Spec.APIProductRef.Name,
		Namespace: apiKey.Namespace,
	}
	if err := r.Get(ctx, apiProductKey, apiProduct); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Error(err, "Referenced APIProduct not found", "apiProduct", apiProductKey)
			setReadyCondition(apiKey, metav1.ConditionFalse, "APIProductNotFound",
				fmt.Sprintf("APIProduct %s not found", apiProductKey))
			if err := r.Status().Update(ctx, apiKey); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		logger.Error(err, "Failed to get APIProduct")
		return ctrl.Result{}, err
	}

	planLimits, err := findPlanLimits(apiProduct, apiKey.Spec.PlanTier)
	if err != nil {
		logger.Error(err, "Plan tier not found in APIProduct", "planTier", apiKey.Spec.PlanTier, "apiProduct", apiProduct.Name)
		setReadyCondition(apiKey, metav1.ConditionFalse, "PlanTierNotFound", fmt.Sprintf("Plan tier %q not found in APIProduct %s", apiKey.Spec.PlanTier, apiProduct.Name))
		if err = r.Status().Update(ctx, apiKey); err != nil {
			return ctrl.Result{}, err
		}
		// Requeue in case APIProduct hasn't finished reconciling
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Set APIProduct as the owner of the APIKey for garbage collection
	if err = controllerutil.SetOwnerReference(apiProduct, apiKey, r.Scheme); err != nil {
		logger.Error(err, "Failed to set owner reference on APIKey")
		return ctrl.Result{}, err
	}

	// Update the APIKey obj
	if err = r.Update(ctx, apiKey); err != nil {
		logger.Error(err, "Failed to update APIProduct after setting OwnerReference")
		return ctrl.Result{}, err
	}

	// Check approval mode
	if apiProduct.Spec.ApprovalMode == apiKeyApprovalModeAutomatic {
		// Automatically approved
		now := metav1.Now()
		apiKey.Status.ReviewedAt = &now
		apiKey.Status.ReviewedBy = "system"
		apiKey.Status.Phase = apiKeyPhaseApproved
		setReadyCondition(apiKey, metav1.ConditionFalse, "AwaitingSecret",
			"API key was automatically approved, waiting for Secret creation")
		logger.Info("Automatically approved APIKey")

	} else {
		// Manual mode - wait for external approval
		apiKey.Status.Phase = apiKeyPhasePending
		setReadyCondition(apiKey, metav1.ConditionFalse, "NotApproved",
			"Request awaiting manual approval")
		logger.Info("APIKey is pending manual approval")
	}

	apiKey.Status.Limits = planLimits

	if err = r.Status().Update(ctx, apiKey); err != nil {
		logger.Error(err, "Failed to update APIKey Status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// reconcileApproved handles APIKeys in the Approved phase.
func (r *APIKeyReconciler) reconcileApproved(ctx context.Context, apiKey *devportalv1alpha1.APIKey) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Check if Secret already exists
	if apiKey.Status.SecretRef != nil {
		secretKey := types.NamespacedName{
			Name:      apiKey.Status.SecretRef.Name,
			Namespace: apiKey.Namespace,
		}
		secret := &corev1.Secret{}
		if err := r.Get(ctx, secretKey, secret); err == nil {
			// Secret exists, nothing more to do
			return ctrl.Result{}, nil
		} else if !apierrors.IsNotFound(err) {
			logger.Error(err, "Failed to check Secret existence")
			return ctrl.Result{}, err
		}
		// Secret was deleted, recreate it
	}

	// Create Secret
	secret, err := createSecret(apiKey)
	if err != nil {
		logger.Error(err, "Failed to create secret")
		return ctrl.Result{}, err
	}

	// Set APIKey as the owner of the Secret for garbage collection
	if err = controllerutil.SetOwnerReference(apiKey, secret, r.Scheme); err != nil {
		logger.Error(err, "Failed to set owner reference on Secret")
		return ctrl.Result{}, err
	}

	// Reconcile creation of the Secret
	if err = r.Create(ctx, secret); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Update existing Secret
			if err := r.Update(ctx, secret); err != nil {
				logger.Error(err, "Failed to update Secret")
				return ctrl.Result{}, err
			}
		} else {
			logger.Error(err, "Failed to create Secret")
			return ctrl.Result{}, err
		}
	}

	logger.Info("Created Secret for APIKey", "secret", secret.Name, "namespace", secret.Namespace)

	// Update status with Secret reference and other metadata
	apiKey.Status.SecretRef = &devportalv1alpha1.SecretReference{
		Name: secret.Name,
		Key:  apiKeySecretKey,
	}

	setReadyCondition(apiKey, metav1.ConditionTrue, "SecretCreated",
		"API key secret has been created successfully")

	if err = r.Status().Update(ctx, apiKey); err != nil {
		logger.Error(err, "Failed to update APIKey status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// reconcileRejected handles APIKeys in the Rejected phase.
func (r *APIKeyReconciler) reconcileRejected(ctx context.Context, apiKey *devportalv1alpha1.APIKey) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Delete the Secret if it exists
	if apiKey.Status.SecretRef != nil {
		secretKey := types.NamespacedName{
			Name:      apiKey.Status.SecretRef.Name,
			Namespace: apiKey.Namespace,
		}
		secret := &corev1.Secret{}
		if err := r.Get(ctx, secretKey, secret); err == nil {
			if err := r.Delete(ctx, secret); err != nil {
				logger.Error(err, "Failed to delete Secret for rejected APIKey")
				return ctrl.Result{}, err
			}
			logger.Info("Deleted Secret for rejected APIKey", "secret", secretKey)
		} else if !apierrors.IsNotFound(err) {
			logger.Error(err, "Failed to get Secret")
			return ctrl.Result{}, err
		}

		// Clear the SecretRef from status
		apiKey.Status.SecretRef = nil
	}

	// Set condition to indicate the APIKey was rejected
	apiKey.Status.Phase = apiKeyPhaseRejected
	setReadyCondition(apiKey, metav1.ConditionFalse, "Rejected",
		"API key request has been rejected")

	if err := r.Status().Update(ctx, apiKey); err != nil {
		logger.Error(err, "Failed to update APIKey status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// setReadyCondition sets the Ready condition on the APIKey status.
func setReadyCondition(apiKey *devportalv1alpha1.APIKey, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&apiKey.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: apiKey.Generation,
	})
}

// generateAPIKey generates a secure random API key.
func generateAPIKey() (string, error) {
	b := make([]byte, apiKeyLength)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// createSecret creates the APIKey Secret
func createSecret(apiKey *devportalv1alpha1.APIKey) (*corev1.Secret, error) {
	// Generate API key
	generatedKey, err := generateAPIKey()
	if err != nil {
		return nil, err
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-apikey-secret", apiKey.Name),
			Namespace: apiKey.Namespace,
			Annotations: map[string]string{
				apiKeySecretAnnotationPlan: apiKey.Spec.PlanTier,
				apiKeySecretAnnotationUser: apiKey.Spec.RequestedBy.UserID,
			},
			Labels: map[string]string{
				"app":                         apiKey.Spec.APIProductRef.Name,
				apiKeySecretLabelAuthorinoKey: apiKeySecretLabelAuthorinoValue,
			},
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			apiKeySecretKey: generatedKey,
		},
	}, nil
}

// findPlanLimits finds the matching plan tier in the APIProduct []Plans to get its limits
func findPlanLimits(apiProduct *devportalv1alpha1.APIProduct, planTier string) (*planpolicyv1alpha1.Limits, error) {
	// Find the matching plan in discoveredPlans
	for _, plan := range apiProduct.Status.DiscoveredPlans {
		if plan.Tier == planTier {
			return &plan.Limits, nil
		}
	}
	return nil, fmt.Errorf("plan tier %q not found in APIProduct %s", planTier, apiProduct.Name)
}

// SetupWithManager sets up the controller with the Manager.
func (r *APIKeyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&devportalv1alpha1.APIKey{}).
		Owns(&corev1.Secret{}).
		Named("apikey").
		Complete(r)
}
