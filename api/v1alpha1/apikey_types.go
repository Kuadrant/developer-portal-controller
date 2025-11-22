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
	planpolicyv1alpha1 "github.com/kuadrant/kuadrant-operator/cmd/extensions/plan-policy/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type APIProductReference struct {
	Name string `json:"name"` // Just name for now, in the future we might want to add KGV.
}

// APIKeySpec defines the desired state of APIKey.
type APIKeySpec struct {
	// Reference to the APIProduct this APIKey belongs to.
	APIProductRef *APIProductReference `json:"apiProductRef"`

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
	// Phase represents the current phase of the APIKey
	// Valid values are "Pending", "Approved", or "Rejected"
	// +kubebuilder:validation:Enum=Pending;Approved;Rejected
	// +optional
	Phase string `json:"phase,omitempty"`

	// APIHostname is the hostname from the HTTPRoute
	// +optional
	APIHostname string `json:"apiHostname,omitempty"`

	// ReviewedBy indicates who approved or rejected the request
	// +optional
	ReviewedBy string `json:"reviewedBy,omitempty"`

	// ReviewedAt is the timestamp when the request was reviewed
	// +optional
	ReviewedAt *metav1.Time `json:"reviewedAt,omitempty"`

	// Limits contains the rate limits for the plan
	// +optional
	Limits *planpolicyv1alpha1.Limits `json:"limits,omitempty"`

	// SecretRef is a reference to the created Secret
	// +optional
	SecretRef *SecretReference `json:"secretRef,omitempty"`

	// Conditions represent the latest available observations of the APIKey's state
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// SecretReference contains a reference to a Secret.
type SecretReference struct {
	// The name of the secret in the Authorino's namespace to select from.
	Name string `json:"name"`

	// The key of the secret to select from.  Must be a valid secret key.
	Key string `json:"key"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=apik
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="API",type=string,JSONPath=`.spec.apiName`
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
