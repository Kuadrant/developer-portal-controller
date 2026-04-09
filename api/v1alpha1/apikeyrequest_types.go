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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type APIKeyReference struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

func (a APIKeyReference) ClientObject() client.ObjectKey {
	return client.ObjectKey{
		Namespace: a.Namespace,
		Name:      a.Name,
	}
}

type LocalAPIProductReference struct {
	Name string `json:"name"`
}

// APIKeyRequestSpec defines the desired state of APIKeyRequest.
type APIKeyRequestSpec struct {
	// Reference to the APIProduct this APIKeyRequest belongs to.
	// +kubebuilder:validation:Required
	APIProductRef LocalAPIProductReference `json:"apiProductRef"`

	// PlanTier is the tier of the plan (e.g., "premium", "basic", "enterprise")
	// +kubebuilder:validation:Required
	PlanTier string `json:"planTier"`

	// UseCase describes how the API key will be used
	// +kubebuilder:validation:Required
	UseCase string `json:"useCase"`

	// RequestedBy contains information about who requested the API key
	// +kubebuilder:validation:Required
	RequestedBy RequestedBy `json:"requestedBy"`

	// Reference to the APIKey this APIKeyRequest belongs to.
	// +kubebuilder:validation:Required
	APIKeyRef APIKeyReference `json:"apiKeyRef"`
}

// APIKeyRequestStatus defines the observed state of APIKeyRequest.
type APIKeyRequestStatus struct {
	// Conditions represent the latest available observations of the APIKeyRequest's state
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// APIKeyRequest is the Schema for the apikeyrequests API.
type APIKeyRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   APIKeyRequestSpec   `json:"spec,omitempty"`
	Status APIKeyRequestStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// APIKeyRequestList contains a list of APIKeyRequest.
type APIKeyRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []APIKeyRequest `json:"items"`
}

func init() {
	SchemeBuilder.Register(&APIKeyRequest{}, &APIKeyRequestList{})
}
