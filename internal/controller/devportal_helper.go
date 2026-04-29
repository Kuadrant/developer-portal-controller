package controller

import (
	"context"
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

// APIKeyRequestName constructs the APIKeyRequest name for a given APIKey
// Pattern: {apiKeyNamespace}-{apiKeyName}
func APIKeyRequestName(apiKey *devportalv1alpha1.APIKey) string {
	return fmt.Sprintf("%s-%s", apiKey.Namespace, apiKey.Name)
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
