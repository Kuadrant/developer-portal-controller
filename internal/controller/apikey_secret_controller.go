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

	devportalv1alpha1 "github.com/kuadrant/developer-portal-controller/api/v1alpha1"
	"github.com/samber/lo"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// kuadrantNamespace is the namespace where enforcement secrets are created
	kuadrantNamespace = "kuadrant"

	// Enforcement secret labels
	enforcementSecretLabelAPIProduct          = "devportal.kuadrant.io/apiproduct"
	enforcementSecretLabelAPIProductNamespace = "devportal.kuadrant.io/apiproduct-namespace"
	enforcementSecretLabelAPIKey              = "devportal.kuadrant.io/apikey"
	enforcementSecretLabelAPIKeyNamespace     = "devportal.kuadrant.io/apikey-namespace"
	enforcementSecretLabelAuthorinoManagedBy  = "authorino.kuadrant.io/managed-by"
)

// APIKeySecretReconciler reconciles enforcement secrets for APIKey approvals/denials
type APIKeySecretReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apikeys,verbs=get;list;watch
// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apikeys/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;delete

// Reconcile handles enforcement secret creation/deletion for all APIKeys
func (r *APIKeySecretReconciler) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)

	logger.V(1).Info("reconciling apikey secrets")
	defer logger.V(1).Info("reconciling apikey secrets: done")

	// List all APIKeys cluster-wide
	apiKeyList := &devportalv1alpha1.APIKeyList{}
	if err := r.List(ctx, apiKeyList); err != nil {
		return ctrl.Result{}, err
	}

	// Filter out APIKeys flagged for deletion
	activeAPIKeyList := lo.Filter(apiKeyList.Items, func(apiKey devportalv1alpha1.APIKey, _ int) bool {
		return apiKey.GetDeletionTimestamp() == nil
	})

	// Track which enforcement secrets should exist
	expectedSecrets := make(map[string]bool)

	// Process each active APIKey
	for idx := range activeAPIKeyList {
		apiKey := &activeAPIKeyList[idx]
		secretName := enforcementSecretName(apiKey)

		err := r.reconcileEnforcementSecret(ctx, apiKey)
		if err != nil {
			if apierrors.IsConflict(err) {
				// Ignore conflicts, resource might just be outdated
				logger.Info("failed to reconcile enforcement secret: resource might just be outdated",
					"apikey", client.ObjectKeyFromObject(apiKey))
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{}, err
		}

		// Track this secret if it should exist (Approved state)
		approvedCondition := meta.FindStatusCondition(apiKey.Status.Conditions, devportalv1alpha1.APIKeyConditionApproved)
		if approvedCondition != nil && approvedCondition.Status == metav1.ConditionTrue {
			expectedSecrets[secretName] = true
		}
	}

	// Cleanup orphaned enforcement secrets (secrets without corresponding APIKeys)
	if err := r.cleanupOrphanedSecrets(ctx, expectedSecrets); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *APIKeySecretReconciler) reconcileEnforcementSecret(ctx context.Context, apiKey *devportalv1alpha1.APIKey) error {
	logger := logf.FromContext(ctx, "apikey", client.ObjectKeyFromObject(apiKey))

	// Check APIKey conditions to determine action
	approvedCondition := meta.FindStatusCondition(apiKey.Status.Conditions, devportalv1alpha1.APIKeyConditionApproved)
	deniedCondition := meta.FindStatusCondition(apiKey.Status.Conditions, devportalv1alpha1.APIKeyConditionDenied)
	failedCondition := meta.FindStatusCondition(apiKey.Status.Conditions, devportalv1alpha1.APIKeyConditionFailed)

	isApproved := approvedCondition != nil && approvedCondition.Status == metav1.ConditionTrue
	isDenied := deniedCondition != nil && deniedCondition.Status == metav1.ConditionTrue
	isFailed := failedCondition != nil && failedCondition.Status == metav1.ConditionTrue

	secretName := enforcementSecretName(apiKey)
	secretKey := client.ObjectKey{
		Namespace: kuadrantNamespace,
		Name:      secretName,
	}

	existingSecret := &corev1.Secret{}
	err := r.Get(ctx, secretKey, existingSecret)
	secretExists := err == nil
	if err != nil && !apierrors.IsNotFound(err) {
		logger.Error(err, "failed to check enforcement secret existence")
		return err
	}

	// Handle Approved state
	if isApproved && !isFailed {
		if !secretExists {
			// Create enforcement secret
			logger.Info("creating enforcement secret for approved APIKey")
			if err := r.createEnforcementSecret(ctx, apiKey); err != nil {
				logger.Error(err, "failed to create enforcement secret")
				// Update APIKey status with failed condition
				return r.setFailedCondition(ctx, apiKey, "EnforcementSecretCreationFailed",
					fmt.Sprintf("Failed to create enforcement secret: %v", err))
			}
			logger.Info("enforcement secret created successfully")
		} else {
			// Secret already exists, nothing to do
			logger.V(1).Info("enforcement secret already exists, skipping creation")
		}
		return nil
	}

	// Handle Denied or Failed state - delete enforcement secret if it exists
	if (isDenied || isFailed) && secretExists {
		logger.Info("deleting enforcement secret for denied/failed APIKey")
		if err := r.Delete(ctx, existingSecret); err != nil {
			if !apierrors.IsNotFound(err) {
				logger.Error(err, "failed to delete enforcement secret")
				return err
			}
		}
		logger.Info("enforcement secret deleted successfully")
		return nil
	}

	// Pending state or secret doesn't exist - nothing to do
	return nil
}

func (r *APIKeySecretReconciler) createEnforcementSecret(ctx context.Context, apiKey *devportalv1alpha1.APIKey) error {
	logger := logf.FromContext(ctx, "apikey", client.ObjectKeyFromObject(apiKey))

	// Read API key value from consumer's secret
	consumerSecret := &corev1.Secret{}
	consumerSecretKey := client.ObjectKey{
		Namespace: apiKey.Namespace,
		Name:      apiKey.Spec.SecretRef.Name,
	}

	if err := r.Get(ctx, consumerSecretKey, consumerSecret); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Error(err, "consumer secret not found")
			return r.setFailedCondition(ctx, apiKey, "SecretNotFound",
				fmt.Sprintf("Consumer secret %s not found", consumerSecretKey))
		}
		logger.Error(err, "failed to read consumer secret")
		return r.setFailedCondition(ctx, apiKey, "SecretReadError",
			fmt.Sprintf("Failed to read consumer secret: %v", err))
	}

	// Verify api_key entry exists in consumer secret
	apiKeyValue, ok := consumerSecret.Data[apiKeySecretKey]
	if !ok {
		logger.Error(nil, "consumer secret does not contain api_key entry")
		return r.setFailedCondition(ctx, apiKey, "SecretAPIKeyNotFound",
			fmt.Sprintf("Consumer secret %s does not contain %q entry", consumerSecretKey, apiKeySecretKey))
	}

	// Create enforcement secret in kuadrant namespace
	enforcementSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      enforcementSecretName(apiKey),
			Namespace: kuadrantNamespace,
			Labels: map[string]string{
				enforcementSecretLabelAPIProduct:          apiKey.Spec.APIProductRef.Name,
				enforcementSecretLabelAPIProductNamespace: apiKey.Spec.APIProductRef.Namespace,
				enforcementSecretLabelAPIKey:              apiKey.Name,
				enforcementSecretLabelAPIKeyNamespace:     apiKey.Namespace,
				enforcementSecretLabelAuthorinoManagedBy:  apiKeySecretLabelAuthorinoValue,
			},
			// Note: Cannot use ownerReferences for cross-namespace resources
			// Controller must handle cleanup explicitly when APIKey is deleted
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			apiKeySecretKey: apiKeyValue,
		},
	}

	if err := r.Create(ctx, enforcementSecret); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Secret already exists, this is OK
			logger.V(1).Info("enforcement secret already exists")
			return nil
		}
		logger.Error(err, "failed to create enforcement secret")
		return err
	}

	return nil
}

func (r *APIKeySecretReconciler) cleanupOrphanedSecrets(ctx context.Context, expectedSecrets map[string]bool) error {
	logger := logf.FromContext(ctx)

	// List all enforcement secrets in kuadrant namespace
	secretList := &corev1.SecretList{}
	listOpts := []client.ListOption{
		client.InNamespace(kuadrantNamespace),
		client.MatchingLabels{
			enforcementSecretLabelAuthorinoManagedBy: apiKeySecretLabelAuthorinoValue,
			// Filter by devportal.kuadrant.io/apikey label to only get our managed secrets
		},
	}

	if err := r.List(ctx, secretList, listOpts...); err != nil {
		logger.Error(err, "failed to list enforcement secrets")
		return err
	}

	// Delete secrets that shouldn't exist
	for i := range secretList.Items {
		secret := &secretList.Items[i]

		// Only cleanup secrets that have our apikey label
		if _, hasLabel := secret.Labels[enforcementSecretLabelAPIKey]; !hasLabel {
			continue
		}

		if !expectedSecrets[secret.Name] {
			logger.Info("deleting orphaned enforcement secret", "secret", secret.Name)
			if err := r.Delete(ctx, secret); err != nil {
				if !apierrors.IsNotFound(err) {
					logger.Error(err, "failed to delete orphaned enforcement secret", "secret", secret.Name)
					return err
				}
			}
		}
	}

	return nil
}

func (r *APIKeySecretReconciler) setFailedCondition(ctx context.Context, apiKey *devportalv1alpha1.APIKey, reason, message string) error {
	logger := logf.FromContext(ctx, "apikey", client.ObjectKeyFromObject(apiKey))

	// Re-fetch the APIKey to get the latest version
	latestAPIKey := &devportalv1alpha1.APIKey{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(apiKey), latestAPIKey); err != nil {
		logger.Error(err, "failed to re-fetch APIKey")
		return err
	}

	// Update conditions
	meta.SetStatusCondition(&latestAPIKey.Status.Conditions, metav1.Condition{
		Type:               devportalv1alpha1.APIKeyConditionFailed,
		Status:             metav1.ConditionTrue,
		ObservedGeneration: latestAPIKey.Generation,
		Reason:             reason,
		Message:            message,
	})

	// Remove Approved and Denied conditions when Failed
	meta.RemoveStatusCondition(&latestAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionApproved)
	meta.RemoveStatusCondition(&latestAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionDenied)

	if err := r.Status().Update(ctx, latestAPIKey); err != nil {
		logger.Error(err, "failed to update APIKey status with failed condition")
		return err
	}

	logger.Info("set failed condition on APIKey", "reason", reason, "message", message)
	return nil
}

// enforcementSecretName generates a unique name for the enforcement secret
// Pattern: devportal-{apikey-namespace}-{apikey-name}
// This prevents naming collisions when multiple APIKeys have the same name in different namespaces
func enforcementSecretName(apiKey *devportalv1alpha1.APIKey) string {
	return fmt.Sprintf("devportal-%s-%s", apiKey.Namespace, apiKey.Name)
}

// SetupWithManager sets up the controller with the Manager.
func (r *APIKeySecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Watches(&devportalv1alpha1.APIKey{}, handler.EnqueueRequestsFromMapFunc(r.enqueueClass)).
		Named("apikey-secret").
		Complete(r)
}

func (r *APIKeySecretReconciler) enqueueClass(_ context.Context, _ client.Object) []ctrl.Request {
	return []ctrl.Request{{NamespacedName: types.NamespacedName{
		Name: string("apikey-secret"),
	}}}
}
