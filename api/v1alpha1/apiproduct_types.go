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
	"github.com/samber/lo"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayapiv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	planpolicyv1alpha1 "github.com/kuadrant/kuadrant-operator/cmd/extensions/plan-policy/api/v1alpha1"
)

const (
	// Status conditions
	StatusConditionReady                string = "Ready"
	StatusConditionPlanPolicyDiscovered string = "PlanPolicyDiscovered"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

type DocumentationSpec struct {
	// URL to openapi specification (json/yaml)
	OpenAPISpecURL *string `json:"openAPISpecURL,omitempty"`

	// URL to swagger ui or similar interactive docs
	SwaggerUI *string `json:"swaggerUI,omitempty"`

	// URL to general documentation
	DocsURL *string `json:"docsURL,omitempty"`

	// URL to git repository (shown as view source in backstage)
	GitRepository *string `json:"gitRepository,omitempty"`

	// techdocs reference (e.g. url:https://github.com/org/repo or dir:. for local docs)
	TechdocsRef *string `json:"techdocsRef,omitempty"`
}

type ContactSpec struct {
	// team name
	Team *string `json:"team,omitempty"`

	// contact email
	Email *string `json:"email,omitempty"`

	// slack channel (e.g. #api-support)
	Slack *string `json:"slack,omitempty"`

	// url to team page or support portal
	Url *string `json:"url,omitempty"`
}

// APIProductSpec defines the desired state of APIProduct.
type APIProductSpec struct {
	// human-readable name for the api product
	DisplayName string `json:"displayName"`

	// detailed description of the api product
	Description *string `json:"description,omitempty"`

	// api version (e.g. v1, v2)
	Version *string `json:"version,omitempty"`

	// whether access requests are auto-approved or require manual review
	// +kubebuilder:validation:Enum=automatic;manual
	// +kubebuilder:default=manual
	ApprovalMode string `json:"approvalMode"`

	// tags for categorisation and search
	Tags []string `json:"tags,omitempty"`

	// reference to the httproute that this api product represents
	// +kubebuilder:validation:XValidation:rule="self.group == 'gateway.networking.k8s.io'",message="Invalid targetRef.group. The only supported value is 'gateway.networking.k8s.io'"
	// +kubebuilder:validation:XValidation:rule="self.kind == 'HTTPRoute'",message="Invalid targetRef.kind. The only supported value is 'HTTPRoute'"
	TargetRef gatewayapiv1alpha2.LocalPolicyTargetReference `json:"targetRef"`

	// api documentation links
	Documentation *DocumentationSpec `json:"documentation,omitempty"`

	// contact information for api owners
	Contact *ContactSpec `json:"contact,omitempty"`

	// controls whether the api product appears in the backstage catalog (Draft = hidden, Published = visible)
	// +kubebuilder:validation:Enum=Draft;Published
	// +kubebuilder:default=Draft
	PublishStatus string `json:"publishStatus"`
}

type PlanSpec struct {
	// Tier this plan represents.
	Tier string `json:"tier"`

	// Limits contains the list of limits that the plan enforces.
	// +optional
	Limits planpolicyv1alpha1.Limits `json:"limits,omitempty"`
}

type OpenAPIStatus struct {
	// raw content
	// +required
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Type=string
	Raw string `json:"raw"`

	// lastSyncTime is the last time the raw content was updated.
	// +required
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Format=date-time
	LastSyncTime metav1.Time `json:"lastSyncTime" protobuf:"bytes,4,opt,name=lastSyncTime"`
}

// APIProductStatus defines the observed state of APIProduct.
type APIProductStatus struct {
	// ObservedGeneration reflects the generation of the most recently observed spec.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// list of planpolicies discovered from httproute
	DiscoveredPlans []PlanSpec `json:"discoveredPlans,omitempty"`

	// OpenAPI specification fetched from the API and its sync status
	// +optional
	OpenAPI *OpenAPIStatus `json:"openapi,omitempty"`

	// Represents the observations of a foo's current state.
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"`
}

func PlanPolicyIntoPlans(plan *planpolicyv1alpha1.PlanPolicy) []PlanSpec {
	if plan == nil {
		return nil
	}

	return lo.Map(plan.Spec.Plans, func(p planpolicyv1alpha1.Plan, _ int) PlanSpec {
		return PlanSpec{Tier: p.Tier, Limits: p.Limits}
	})
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`,description="APIProduct Ready",priority=2
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// APIProduct is the Schema for the apiproducts API.
type APIProduct struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   APIProductSpec   `json:"spec,omitempty"`
	Status APIProductStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// APIProductList contains a list of APIProduct.
type APIProductList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []APIProduct `json:"items"`
}

func init() {
	SchemeBuilder.Register(&APIProduct{}, &APIProductList{})
}
