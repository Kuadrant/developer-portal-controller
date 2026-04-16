package controller

import (
	"context"
	"fmt"

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
		return &devportalv1alpha1.APIKeyList{}
	}
	return apiKeys
}

func WithAPIKeyRequests(ctx context.Context, apiKeyRequests *devportalv1alpha1.APIKeyRequestList) context.Context {
	return context.WithValue(ctx, apiKeyRequestCtxKey, apiKeyRequests)
}

func GetAPIKeyRequests(ctx context.Context) *devportalv1alpha1.APIKeyRequestList {
	apiKeyRequests, ok := ctx.Value(apiKeyRequestCtxKey).(*devportalv1alpha1.APIKeyRequestList)
	if !ok {
		return &devportalv1alpha1.APIKeyRequestList{}
	}
	return apiKeyRequests
}

func WithAPIKeyApprovals(ctx context.Context, apiKeyApprovals *devportalv1alpha1.APIKeyApprovalList) context.Context {
	return context.WithValue(ctx, apiKeyApprovalsCtxKey, apiKeyApprovals)
}

func GetAPIKeyApprovals(ctx context.Context) *devportalv1alpha1.APIKeyApprovalList {
	apiKeyApprovals, ok := ctx.Value(apiKeyApprovalsCtxKey).(*devportalv1alpha1.APIKeyApprovalList)
	if !ok {
		return &devportalv1alpha1.APIKeyApprovalList{}
	}
	return apiKeyApprovals
}

// APIKeyRequestName constructs the APIKeyRequest name for a given APIKey
// Pattern: {apiKeyNamespace}-{apiKeyName}
func APIKeyRequestName(apiKey *devportalv1alpha1.APIKey) string {
	return fmt.Sprintf("%s-%s", apiKey.Namespace, apiKey.Name)
}
