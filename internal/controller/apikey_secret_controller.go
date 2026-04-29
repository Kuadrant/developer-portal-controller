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
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/samber/lo"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	devportalv1alpha1 "github.com/kuadrant/developer-portal-controller/api/v1alpha1"
	"github.com/kuadrant/developer-portal-controller/internal/reconcilers"
)

const (
	apiKeySecretAnnotationPlan      = "secret.kuadrant.io/plan-id"
	apiKeySecretAnnotationUser      = "secret.kuadrant.io/user-id"
	apiKeySecretLabelAuthorinoValue = "authorino"
	apiKeySecretKey                 = "api_key"
	// Enforcement secret labels
	enforcementSecretLabelAPIProduct          = "devportal.kuadrant.io/apiproduct"
	enforcementSecretLabelAPIProductNamespace = "devportal.kuadrant.io/apiproduct-namespace"
	enforcementSecretLabelAPIKey              = "devportal.kuadrant.io/apikey"
	enforcementSecretLabelAPIKeyNamespace     = "devportal.kuadrant.io/apikey-namespace"
	enforcementSecretLabelAuthorinoManagedBy  = "authorino.kuadrant.io/managed-by"
)

// APIKeySecretReconciler reconciles enforcement secrets for APIKey approvals/denials
type APIKeySecretReconciler struct {
	reconcilers.BaseReconciler
}

// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apikeys,verbs=get;list;watch
// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apiproducts,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups=kuadrant.io,resources=kuadrants,verbs=get;list;watch

// Reconcile handles enforcement secret creation/deletion for all APIKeys
func (r *APIKeySecretReconciler) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)

	logger.V(1).Info("reconciling apikey secrets")
	defer logger.V(1).Info("reconciling apikey secrets: done")

	// Get Kuadrant namespace - if not found, skip processing
	// The status controller will set Failed condition if Kuadrant CR doesn't exist
	kuadrantNamespace, err := GetKuadrantNamespace(ctx, r.Client)
	if err != nil {
		return ctrl.Result{}, nil
	}

	if kuadrantNamespace == "" {
		logger.V(1).Info("Kuadrant CR not found, skipping enforcement secret reconciliation")
		return ctrl.Result{}, nil
	}

	// List all APIKeys cluster-wide
	apiKeyList := &devportalv1alpha1.APIKeyList{}
	if err := r.List(ctx, apiKeyList); err != nil {
		return ctrl.Result{}, err
	}

	// Filter out APIKeys flagged for deletion
	activeAPIKeyList := lo.Filter(apiKeyList.Items, func(apiKey devportalv1alpha1.APIKey, _ int) bool {
		return apiKey.GetDeletionTimestamp() == nil
	})

	deletingAPIKeyList := lo.Filter(apiKeyList.Items, func(apiKey devportalv1alpha1.APIKey, _ int) bool {
		return apiKey.GetDeletionTimestamp() != nil
	})

	approvedAPIKeyList := lo.Filter(activeAPIKeyList, func(apiKey devportalv1alpha1.APIKey, _ int) bool {
		return apiKey.IsApproved()
	})

	notApprovedAPIKeyList := lo.Filter(activeAPIKeyList, func(apiKey devportalv1alpha1.APIKey, _ int) bool {
		return !apiKey.IsApproved()
	})

	// Process each active and approved APIKey
	for idx := range approvedAPIKeyList {
		apiKey := &approvedAPIKeyList[idx]

		enforcementSecret, err := r.desiredEnforcementSecret(ctx, apiKey, kuadrantNamespace)
		if err != nil {
			logger.Error(err, "failed to generate desired enforcement secret", "apiKey", client.ObjectKeyFromObject(apiKey))
			return ctrl.Result{}, err
		}
		if enforcementSecret == nil {
			// This should never happen - desiredEnforcementSecret always returns either (secret, nil) or (nil, error)
			err := fmt.Errorf("desiredEnforcementSecret returned nil secret without error for APIKey %s/%s", apiKey.Namespace, apiKey.Name)
			logger.Error(err, "unexpected nil enforcement secret")
			return ctrl.Result{}, err
		}
		_, err = r.ReconcileResource(ctx, &corev1.Secret{}, enforcementSecret, reconcilers.CreateOnlyMutator)
		if err != nil {
			logger.Error(err, "Failed to reconcile enforcement secret", "apiKey", client.ObjectKeyFromObject(apiKey))
			return ctrl.Result{}, err
		}
	}

	// Process each deleting or not-approved APIKey - delete their enforcement secrets
	toDeleteList := append(deletingAPIKeyList, notApprovedAPIKeyList...)
	for idx := range toDeleteList {
		apiKey := &toDeleteList[idx]
		enforcementSecret := &corev1.Secret{}
		enforcementSecret.Name = enforcementSecretName(apiKey)
		enforcementSecret.Namespace = kuadrantNamespace
		reconcilers.TagObjectToDelete(enforcementSecret)
		if _, err := r.ReconcileResource(ctx, &corev1.Secret{}, enforcementSecret, reconcilers.CreateOnlyMutator); err != nil {
			logger.Error(err, "Failed to delete enforcement secret for deleting APIKey", "apiKey", client.ObjectKeyFromObject(apiKey))
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *APIKeySecretReconciler) desiredEnforcementSecret(ctx context.Context, apiKey *devportalv1alpha1.APIKey, kuadrantNamespace string) (*corev1.Secret, error) {
	if !apiKey.IsApproved() {
		return nil, fmt.Errorf("trying to compute enforcement secret for APIKey %s/%s not approved, this indicates the secret was deleted after approval or a race condition occurred", apiKey.Namespace, apiKey.Name)
	}
	// Read API key value from consumer's secret
	// Note: The apikey_status_controller validates the secret and sets Failed condition if needed
	consumerSecret := &corev1.Secret{}
	consumerSecretKey := client.ObjectKey{
		Namespace: apiKey.Namespace,
		Name:      apiKey.Spec.SecretRef.Name,
	}

	if err := r.Get(ctx, consumerSecretKey, consumerSecret); err != nil {
		if apierrors.IsNotFound(err) {
			// This should never happen for approved APIKeys - the status controller validates the secret exists
			// and sets Failed condition if missing. If we reach here, it indicates a race condition or
			// the secret was deleted after approval.
			return nil, fmt.Errorf("consumer secret %s not found for approved APIKey %s/%s - this indicates the secret was deleted after approval or a race condition occurred",
				consumerSecretKey, apiKey.Namespace, apiKey.Name)
		}
		// Other errors (permission denied, network issues, etc.)
		return nil, fmt.Errorf("failed to read consumer secret %s for APIKey %s/%s: %w",
			consumerSecretKey, apiKey.Namespace, apiKey.Name, err)
	}

	// Get api_key entry from consumer secret
	apiKeyValue, ok := consumerSecret.Data[apiKeySecretKey]
	if !ok {
		// This should never happen for approved APIKeys - the status controller validates the api_key entry exists
		// and sets Failed condition if missing. If we reach here, it indicates a race condition or
		// the secret was modified after approval.
		return nil, fmt.Errorf("consumer secret %s is missing '%s' entry for approved APIKey %s/%s - this indicates the secret was modified after approval or a race condition occurred",
			consumerSecretKey, apiKeySecretKey, apiKey.Namespace, apiKey.Name)
	}

	// Check if the api_key entry is not empty
	if len(apiKeyValue) == 0 {
		// This should never happen for approved APIKeys - the status controller validates the api_key entry is not empty
		// and sets Failed condition if empty. If we reach here, it indicates a race condition or
		// the secret was modified after approval.
		return nil, fmt.Errorf("consumer secret %s has empty '%s' entry for approved APIKey %s/%s - this indicates the secret was modified after approval or a race condition occurred",
			consumerSecretKey, apiKeySecretKey, apiKey.Namespace, apiKey.Name)
	}

	secretLabels := map[string]string{
		enforcementSecretLabelAPIProduct:          apiKey.Spec.APIProductRef.Name,
		enforcementSecretLabelAPIProductNamespace: apiKey.Spec.APIProductRef.Namespace,
		enforcementSecretLabelAPIKey:              apiKey.Name,
		enforcementSecretLabelAPIKeyNamespace:     apiKey.Namespace,
		enforcementSecretLabelAuthorinoManagedBy:  apiKeySecretLabelAuthorinoValue,
	}

	if apiKey.Status.AuthScheme != nil &&
		apiKey.Status.AuthScheme.AuthenticationSpec != nil &&
		apiKey.Status.AuthScheme.AuthenticationSpec.Selector != nil {
		secretLabels = lo.Assign(apiKey.Status.AuthScheme.AuthenticationSpec.Selector.MatchLabels,
			secretLabels)
	}

	// Create enforcement secret in kuadrant namespace
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      enforcementSecretName(apiKey),
			Namespace: kuadrantNamespace,
			Annotations: map[string]string{
				apiKeySecretAnnotationPlan: apiKey.Spec.PlanTier,
				apiKeySecretAnnotationUser: apiKey.Spec.RequestedBy.UserID,
			},
			Labels: secretLabels,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			apiKeySecretKey: apiKeyValue,
		},
	}, nil
}

// enforcementSecretName generates a unique name for the enforcement secret
// Pattern: devportal-{apikey-namespace}-{apikey-name}
// This prevents naming collisions when multiple APIKeys have the same name in different namespaces
func enforcementSecretName(apiKey *devportalv1alpha1.APIKey) string {
	// Create unique identifier from namespace and name
	identifier := fmt.Sprintf("%s/%s", apiKey.Namespace, apiKey.Name)

	// Generate hash suffix to prevent collisions between ambiguous namespace/name pairs
	// e.g., "foo-bar/baz" vs "foo/bar-baz" would both produce "devportal-foo-bar-baz"
	// without the hash suffix
	hash := sha256.Sum256([]byte(identifier))
	hashSuffix := hex.EncodeToString(hash[:])[:8] // Hex encoding produces [0-9a-f], all DNS-1123 valid

	// DNS-1123 compliant: max length 146 chars (< 253 limit)
	// - Namespace and name are already validated as DNS-1123 labels by Kubernetes
	// - Hex suffix contains only lowercase alphanumeric [0-9a-f], guaranteed DNS-1123 compliant
	return fmt.Sprintf("devportal-%s-%s-%s", apiKey.Namespace, apiKey.Name, hashSuffix)
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
