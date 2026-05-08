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
)

// APIKeyApproval condition types
const (
	// APIKeyApprovalConditionValid indicates the APIKeyApproval is valid and references an existing APIKeyRequest
	APIKeyApprovalConditionValid string = "Valid"
)

type APIKeyRequestReference struct {
	Name string `json:"name"`
}

// APIKeyApprovalSpec defines the desired state of APIKeyApproval.
type APIKeyApprovalSpec struct {
	// Reference to the APIKeyRequest
	// +kubebuilder:validation:Required
	APIKeyRequestRef APIKeyRequestReference `json:"apiKeyRequestRef"`

	// Approved indicates whether the API key request is approved
	// +kubebuilder:validation:Required
	Approved bool `json:"approved"`

	// ReviewedBy contains the identifier of the person who reviewed the request
	// +kubebuilder:validation:Required
	ReviewedBy string `json:"reviewedBy"`

	// ReviewedAt is the timestamp when the request was reviewed
	// +kubebuilder:validation:Required
	ReviewedAt metav1.Time `json:"reviewedAt"`

	// Reason for the approval or denial decision
	// +optional
	Reason string `json:"reason,omitempty"`

	// Message provides additional context about the approval or denial
	// +optional
	Message string `json:"message,omitempty"`
}

// APIKeyApprovalStatus defines the observed state of APIKeyApproval.
type APIKeyApprovalStatus struct {
	// ObservedGeneration reflects the generation of the most recently observed spec.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions represent the latest available observations of the APIKeyApproval's state
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// APIKeyApproval is the Schema for the apikeyapprovals API.
type APIKeyApproval struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   APIKeyApprovalSpec   `json:"spec,omitempty"`
	Status APIKeyApprovalStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// APIKeyApprovalList contains a list of APIKeyApproval.
type APIKeyApprovalList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []APIKeyApproval `json:"items"`
}

func init() {
	SchemeBuilder.Register(&APIKeyApproval{}, &APIKeyApprovalList{})
}
