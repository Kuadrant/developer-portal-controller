package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	kuadrantv1beta1 "github.com/kuadrant/kuadrant-operator/api/v1beta1"

	devportalv1alpha1 "github.com/kuadrant/developer-portal-controller/api/v1alpha1"
)

type apiKeysCtxKeyType string
type apiKeyRequestsCtxKeyType string
type apiKeyApprovalsCtxKeyType string

const apiKeysCtxKey apiKeysCtxKeyType = "apikeys"
const apiKeyRequestCtxKey apiKeyRequestsCtxKeyType = "apikeyrequests"
const apiKeyApprovalsCtxKey apiKeyApprovalsCtxKeyType = "apikeyapprovals"

func WithAPIKeys(ctx context.Context, apiKeys *devportalv1alpha1.APIKeyList) context.Context {
	return context.WithValue(ctx, apiKeysCtxKey, apiKeys)
}

func GetAPIKeys(ctx context.Context) *devportalv1alpha1.APIKeyList {
	apiKeys, ok := ctx.Value(apiKeysCtxKey).(*devportalv1alpha1.APIKeyList)
	if !ok {
		return nil
	}
	return apiKeys
}

func WithAPIKeyRequests(ctx context.Context, apiKeyRequests *devportalv1alpha1.APIKeyRequestList) context.Context {
	return context.WithValue(ctx, apiKeyRequestCtxKey, apiKeyRequests)
}

func GetAPIKeyRequests(ctx context.Context) *devportalv1alpha1.APIKeyRequestList {
	apiKeyRequests, ok := ctx.Value(apiKeyRequestCtxKey).(*devportalv1alpha1.APIKeyRequestList)
	if !ok {
		return nil
	}
	return apiKeyRequests
}

func WithAPIKeyApprovals(ctx context.Context, apiKeyApprovals *devportalv1alpha1.APIKeyApprovalList) context.Context {
	return context.WithValue(ctx, apiKeyApprovalsCtxKey, apiKeyApprovals)
}

func GetAPIKeyApprovals(ctx context.Context) *devportalv1alpha1.APIKeyApprovalList {
	apiKeyApprovals, ok := ctx.Value(apiKeyApprovalsCtxKey).(*devportalv1alpha1.APIKeyApprovalList)
	if !ok {
		return nil
	}
	return apiKeyApprovals
}

// APIKeyRequestName generates a unique name for the APIKeyRequest
// Pattern: {apikey-namespace}-{apikey-name}-{hash}
// The hash ensures a deterministic 1:1 mapping from APIKey to APIKeyRequest - no two APIKeys
// can produce the same name. If the APIKeyRequest already exists, the controller updates it
// to sync with the APIKey state, making reconciliation idempotent.
func APIKeyRequestName(apiKey *devportalv1alpha1.APIKey) string {
	// Create unique identifier from namespace and name
	identifier := fmt.Sprintf("%s/%s", apiKey.Namespace, apiKey.Name)

	// Generate hash suffix to prevent collisions between ambiguous namespace/name pairs
	// e.g., "foo-bar/baz" vs "foo/bar-baz" would both produce "foo-bar-baz"
	// without the hash suffix
	hash := sha256.Sum256([]byte(identifier))
	hashSuffix := hex.EncodeToString(hash[:])[:8] // Hex encoding produces [0-9a-f], all DNS-1123 valid

	// DNS-1123 compliant: max length 138 chars (< 253 limit)
	// - Namespace and name are already validated as DNS-1123 labels by Kubernetes
	// - Hex suffix contains only lowercase alphanumeric [0-9a-f], guaranteed DNS-1123 compliant
	return fmt.Sprintf("%s-%s-%s", apiKey.Namespace, apiKey.Name, hashSuffix)
}

// GetKuadrantNamespace finds the namespace where the Kuadrant CR exists
// Returns the namespace name and true if found, empty string and false otherwise
func GetKuadrantNamespace(ctx context.Context, k8sClient client.Client) (string, error) {
	logger := logf.FromContext(ctx)
	kuadrantList := &kuadrantv1beta1.KuadrantList{}
	if err := k8sClient.List(ctx, kuadrantList); err != nil {
		logger.Error(err, "cannot list kuadrant resources")
		return "", err
	}

	if len(kuadrantList.Items) == 0 {
		return "", nil
	}

	// Return the namespace of the first Kuadrant CR found
	return kuadrantList.Items[0].Namespace, nil
}
