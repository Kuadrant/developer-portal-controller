package controller

import (
	"fmt"

	devportalv1alpha1 "github.com/kuadrant/developer-portal-controller/api/v1alpha1"
)

// APIKeyRequestName constructs the APIKeyRequest name for a given APIKey
// Pattern: {apiKeyNamespace}-{apiKeyName}
func APIKeyRequestName(apiKey *devportalv1alpha1.APIKey) string {
	return fmt.Sprintf("%s-%s", apiKey.Namespace, apiKey.Name)
}
