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
	apiKeyFinalizer                 = "devportal.kuadrant.io/apikey-finalizer"
	apiKeySecretAnnotationPlan      = "secret.kuadrant.io/plan-id"
	apiKeySecretAnnotationUser      = "secret.kuadrant.io/user-id"
	apiKeySecretLabelAuthorinoKey   = "authorino.kuadrant.io/managed-by"
	apiKeySecretLabelAuthorinoValue = "authorino"
	apiKeySecretKey                 = "api-key"
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

	// Handle deletion
	if !apiKey.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, apiKey)
	}

	// Add finalizer if it doesn't exist
	if !controllerutil.ContainsFinalizer(apiKey, apiKeyFinalizer) {
		controllerutil.AddFinalizer(apiKey, apiKeyFinalizer)
		if err := r.Update(ctx, apiKey); err != nil {
			logger.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
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
		// Nothing to do for rejected keys
		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

// reconcileDelete handles the deletion of an APIKey and cleans up the associated Secret.
func (r *APIKeyReconciler) reconcileDelete(ctx context.Context, apiKey *devportalv1alpha1.APIKey) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Delete the Secret if it exists
	if apiKey.Status.SecretRef != nil {
		secret := &corev1.Secret{}
		secretKey := types.NamespacedName{
			Name:      apiKey.Status.SecretRef.Name,
			Namespace: apiKey.Namespace,
		}
		if err := r.Get(ctx, secretKey, secret); err == nil {
			if err := r.Delete(ctx, secret); err != nil {
				logger.Error(err, "Failed to delete Secret")
				return ctrl.Result{}, err
			}
			logger.Info("Deleted Secret", "secret", secretKey)
		} else if !apierrors.IsNotFound(err) {
			logger.Error(err, "Failed to get Secret")
			return ctrl.Result{}, err
		}
	}

	// Remove finalizer
	controllerutil.RemoveFinalizer(apiKey, apiKeyFinalizer)
	if err := r.Update(ctx, apiKey); err != nil {
		logger.Error(err, "Failed to remove finalizer")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// reconcilePending handles APIKeys in the Pending phase.
func (r *APIKeyReconciler) reconcilePending(ctx context.Context, apiKey *devportalv1alpha1.APIKey) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	now := metav1.Now()
	apiKey.Status.ReviewedBy = "system"
	apiKey.Status.ReviewedAt = &now

	// Check approval mode
	if apiKey.Spec.ApprovalMode == apiKeyApprovalModeAutomatic {
		// Automatically approved
		apiKey.Status.Phase = apiKeyPhaseApproved
		// Set condition
		meta.SetStatusCondition(&apiKey.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			Reason:             "AwaitingSecret",
			Message:            "API key was automatically approved, waiting for Secret creation",
			ObservedGeneration: apiKey.Generation,
		})
		logger.Info("Automatically approved APIKey")

	} else {
		// Manual mode - wait for external approval
		// Set condition
		meta.SetStatusCondition(&apiKey.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			Reason:             "NotApproved",
			Message:            "Request awaiting manual approval",
			ObservedGeneration: apiKey.Generation,
		})
		logger.Info("APIKey is pending manual approval")
	}

	if err := r.Status().Update(ctx, apiKey); err != nil {
		logger.Error(err, "Failed to approve APIKey")
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

	// Fetch the APIProduct to get additional metadata
	apiProduct := &devportalv1alpha1.APIProduct{}
	apiProductKey := types.NamespacedName{
		Name:      apiKey.Spec.APIName,
		Namespace: apiKey.Spec.APINamespace,
	}
	if err := r.Get(ctx, apiProductKey, apiProduct); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Error(err, "Referenced APIProduct not found", "apiProduct", apiProductKey)
			meta.SetStatusCondition(&apiKey.Status.Conditions, metav1.Condition{
				Type:               "Ready",
				Status:             metav1.ConditionFalse,
				Reason:             "APIProductNotFound",
				Message:            fmt.Sprintf("APIProduct %s not found", apiProductKey),
				ObservedGeneration: apiKey.Generation,
			})
			if err := r.Status().Update(ctx, apiKey); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		logger.Error(err, "Failed to get APIProduct")
		return ctrl.Result{}, err
	}

	// Generate API key
	generatedKey, err := generateAPIKey()
	if err != nil {
		logger.Error(err, "Failed to generate API key")
		return ctrl.Result{}, err
	}

	// Create Secret in the APIProduct's namespace
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-apikey", apiKey.Name),
			Namespace: apiKey.Spec.APINamespace,
			Annotations: map[string]string{
				apiKeySecretAnnotationPlan: apiKey.Spec.PlanTier,
				apiKeySecretAnnotationUser: apiKey.Spec.RequestedBy.UserID,
			},
			Labels: map[string]string{
				"app":                         apiKey.Spec.APIName,
				apiKeySecretLabelAuthorinoKey: apiKeySecretLabelAuthorinoValue,
			},
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			apiKeySecretKey: generatedKey,
		},
	}

	// Set APIProduct as the owner of the Secret for garbage collection
	if err := controllerutil.SetOwnerReference(apiProduct, secret, r.Scheme); err != nil {
		logger.Error(err, "Failed to set owner reference on Secret")
		return ctrl.Result{}, err
	}

	// Create the Secret
	if err := r.Create(ctx, secret); err != nil {
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

	// Set condition
	meta.SetStatusCondition(&apiKey.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "SecretCreated",
		Message:            "API key secret has been created successfully",
		ObservedGeneration: apiKey.Generation,
	})

	if err := r.Status().Update(ctx, apiKey); err != nil {
		logger.Error(err, "Failed to update APIKey status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// generateAPIKey generates a secure random API key.
func generateAPIKey() (string, error) {
	b := make([]byte, apiKeyLength)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *APIKeyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&devportalv1alpha1.APIKey{}).
		Owns(&corev1.Secret{}).
		Named("apikey").
		Complete(r)
}
