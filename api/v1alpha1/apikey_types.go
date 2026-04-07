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

package v1alpha1

import (
	authorinov1beta3 "github.com/kuadrant/authorino/api/v1beta3"
	planpolicyv1alpha1 "github.com/kuadrant/kuadrant-operator/cmd/extensions/plan-policy/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// APIKey condition types
const (
	// APIKeyConditionApproved indicates the APIKey has been approved by the API owner
	APIKeyConditionApproved string = "Approved"

	// APIKeyConditionDenied indicates the APIKey request has been denied by the API owner
	APIKeyConditionDenied string = "Denied"

	// APIKeyConditionFailed indicates the APIKey processing has failed
	APIKeyConditionFailed string = "Failed"
)

type APIProductReference struct {
	Name      string `json:"name"` // Just name for now, in the future we might want to add KGV.
	Namespace string `json:"namespace"`
}

// APIKeySpec defines the desired state of APIKey.
type APIKeySpec struct {
	// Reference to the APIProduct this APIKey belongs to.
	// +kubebuilder:validation:Required
	APIProductRef APIProductReference `json:"apiProductRef"`

	// PlanTier is the tier of the plan (e.g., "premium", "basic", "enterprise")
	// +kubebuilder:validation:Required
	PlanTier string `json:"planTier"`

	// UseCase describes how the API key will be used
	// +kubebuilder:validation:Required
	UseCase string `json:"useCase"`

	// RequestedBy contains information about who requested the API key
	// +kubebuilder:validation:Required
	RequestedBy RequestedBy `json:"requestedBy"`
}

// RequestedBy contains information about the requester.
type RequestedBy struct {
	// UserID is the identifier of the user requesting the API key
	// +kubebuilder:validation:Required
	UserID string `json:"userId"`

	// Email is the email address of the user
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	Email string `json:"email"`
}

// APIKeyStatus defines the observed state of APIKey.
type APIKeyStatus struct {
	// APIHostname is the hostname from the HTTPRoute
	// +optional
	APIHostname string `json:"apiHostname,omitempty"`

	// APIKeyValue is the projected API key value from the secret
	// Exposes the secret value to consumer without requiring secret read permissions
	// +optional
	APIKeyValue string `json:"apiKeyValue,omitempty"`

	// Limits contains the rate limits for the plan
	// +optional
	Limits *planpolicyv1alpha1.Limits `json:"limits,omitempty"`

	// AuthScheme displays the APIKey AuthScheme
	// +optional
	AuthScheme *AuthScheme `json:"authScheme,omitempty"`

	// Conditions represent the latest available observations of the APIKey's state
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// AuthScheme describes the APIKey AuthScheme defined in the Kuadrant AuthPolicy for the HTTPRoute targeting the APIProduct
type AuthScheme struct {
	AuthenticationSpec *authorinov1beta3.ApiKeyAuthenticationSpec `json:"authenticationSpec,omitempty"`
	Credentials        *authorinov1beta3.Credentials              `json:"credentials,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=apik
// +kubebuilder:printcolumn:name="Approved",type=string,JSONPath=`.status.conditions[?(@.type=="Approved")].status`
// +kubebuilder:printcolumn:name="API",type=string,JSONPath=`.spec.apiProductRef.name`
// +kubebuilder:printcolumn:name="Plan",type=string,JSONPath=`.spec.planTier`
// +kubebuilder:printcolumn:name="User",type=string,JSONPath=`.spec.requestedBy.userId`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// APIKey is the Schema for the apikeys API.
type APIKey struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   APIKeySpec   `json:"spec,omitempty"`
	Status APIKeyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// APIKeyList contains a list of APIKey.
type APIKeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []APIKey `json:"items"`
}

func init() {
	SchemeBuilder.Register(&APIKey{}, &APIKeyList{})
}
