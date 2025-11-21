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

package controller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"

	"github.com/samber/lo"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	planpolicyv1alpha1 "github.com/kuadrant/kuadrant-operator/cmd/extensions/plan-policy/api/v1alpha1"

	devportalv1alpha1 "github.com/kuadrant/developer-portal-controller/api/v1alpha1"
)

// HTTPClient is an interface for making HTTP requests
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// APIProductReconciler reconciles a APIProduct object
type APIProductReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	HTTPClient HTTPClient
}

// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apiproducts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apiproducts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=devportal.kuadrant.io,resources=apiproducts/finalizers,verbs=update

// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes/status,verbs=get

// +kubebuilder:rbac:groups=extensions.kuadrant.io,resources=planpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=extensions.kuadrant.io,resources=planpolicies/status,verbs=get

// Reconcile handles reconciling all resources in a single call. Any resource event should enqueue the
// same reconcile.Request containing this controller name, i.e. "apiproduct". This allows multiple resource updates to
// be handled by a single call to Reconcile. The reconcile.Request DOES NOT map to a specific resource.
func (r *APIProductReconciler) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)

	logger.V(1).Info("reconciling apiproducts")
	defer logger.V(1).Info("reconciling apiproducts: done")

	planList := &planpolicyv1alpha1.PlanPolicyList{}
	err := r.List(ctx, planList)
	if err != nil {
		return ctrl.Result{}, err
	}

	ctx = WithPlanPolicies(ctx, planList)

	apiProductListRaw := &devportalv1alpha1.APIProductList{}
	err = r.List(ctx, apiProductListRaw)
	if err != nil {
		return ctrl.Result{}, err
	}

	// filter out flagged for deletion
	apiProductList := lo.Filter(apiProductListRaw.Items, func(api devportalv1alpha1.APIProduct, _ int) bool {
		return api.GetDeletionTimestamp() == nil
	})

	for idx := range apiProductList {
		err := r.reconcileStatus(ctx, &apiProductList[idx])
		if err != nil {
			if apierrors.IsConflict(err) {
				// Ignore conflicts, resource might just be outdated.
				logger.Info("failed to update status: resource might just be outdated")
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *APIProductReconciler) reconcileStatus(ctx context.Context, apiProductObj *devportalv1alpha1.APIProduct) error {
	logger := logf.FromContext(ctx, "apiproduct", client.ObjectKeyFromObject(apiProductObj))

	newStatus, err := r.calculateStatus(ctx, apiProductObj)
	if err != nil {
		return err
	}

	equalStatus := equality.Semantic.DeepEqual(newStatus, apiProductObj.Status)
	if equalStatus && apiProductObj.Generation == apiProductObj.Status.ObservedGeneration {
		logger.V(1).Info("apiproduct status unchanged, skipping update")
		return nil
	}
	apiProductObj.Status = *newStatus

	updateErr := r.Client.Status().Update(ctx, apiProductObj)
	if updateErr != nil {
		return updateErr
	}

	logger.Info("status updated")

	return nil
}

func (r *APIProductReconciler) calculateStatus(ctx context.Context, apiProductObj *devportalv1alpha1.APIProduct) (*devportalv1alpha1.APIProductStatus, error) {
	newStatus := &devportalv1alpha1.APIProductStatus{
		ObservedGeneration: apiProductObj.Generation,
		// Copy initial conditions. Otherwise, status will always be updated
		Conditions: slices.Clone(apiProductObj.Status.Conditions),
	}

	if apiProductObj.Status.OpenAPI != nil {
		// Copy initial openapi. Otherwise, content will be fetched always
		newStatus.OpenAPI = ptr.To(*apiProductObj.Status.OpenAPI)
	}

	planPolicy, err := r.findPlanPolicyForAPIProduct(ctx, apiProductObj)
	if err != nil {
		return nil, err
	}

	newStatus.DiscoveredPlans = devportalv1alpha1.PlanPolicyIntoPlans(planPolicy)

	planPolicyDiscoveredCond, err := r.planPolicyDiscoveredCondition(ctx, apiProductObj)
	if err != nil {
		return nil, err
	}

	meta.SetStatusCondition(&newStatus.Conditions, *planPolicyDiscoveredCond)

	readyCond, err := r.readyCondition(ctx, apiProductObj)
	if err != nil {
		return nil, err
	}

	meta.SetStatusCondition(&newStatus.Conditions, *readyCond)

	openAPIStatus, err := r.openAPIStatus(ctx, apiProductObj)
	if err != nil {
		return nil, err
	}

	newStatus.OpenAPI = openAPIStatus

	return newStatus, nil
}

func (r *APIProductReconciler) readyCondition(ctx context.Context, apiProductObj *devportalv1alpha1.APIProduct) (*metav1.Condition, error) {
	cond := &metav1.Condition{
		Type: devportalv1alpha1.StatusConditionReady,
	}

	route := &gwapiv1.HTTPRoute{}
	rKey := client.ObjectKey{ // Its deployment is built after the same name and namespace
		Namespace: apiProductObj.Namespace,
		Name:      string(apiProductObj.Spec.TargetRef.Name),
	}
	err := r.Get(ctx, rKey, route)
	if client.IgnoreNotFound(err) != nil {
		return nil, err
	}

	if apierrors.IsNotFound(err) {
		cond.Status = metav1.ConditionFalse
		cond.Reason = "HTTPRouteNotFound"
		cond.Message = fmt.Sprintf("HTTPRoute %s not found", rKey)
		return cond, nil
	}

	httpRouteConditions := lo.FlatMap(route.Status.Parents, func(parent gwapiv1.RouteParentStatus, _ int) []metav1.Condition {
		return parent.Conditions
	})

	accepted := lo.ContainsBy(httpRouteConditions, func(cond metav1.Condition) bool {
		return cond.Type == string(gwapiv1.RouteConditionAccepted) && cond.Status == metav1.ConditionTrue
	})

	if accepted {
		cond.Status = metav1.ConditionTrue
		cond.Reason = "HTTPRouteAccepted"
		cond.Message = fmt.Sprintf("HTTPRoute %s accepted", rKey)
		return cond, nil
	}

	cond.Status = metav1.ConditionFalse
	cond.Reason = "HTTPRouteNotAccepted"
	cond.Message = fmt.Sprintf("HTTPRoute %s not accepted", rKey)

	return cond, nil
}

func (r *APIProductReconciler) planPolicyDiscoveredCondition(ctx context.Context, apiProductObj *devportalv1alpha1.APIProduct) (*metav1.Condition, error) {
	cond := &metav1.Condition{
		Type:   devportalv1alpha1.StatusConditionPlanPolicyDiscovered,
		Status: metav1.ConditionTrue,
		Reason: "Found",
	}

	planPolicy, err := r.findPlanPolicyForAPIProduct(ctx, apiProductObj)
	if err != nil {
		return nil, err
	}

	if planPolicy == nil {
		cond.Status = metav1.ConditionFalse
		cond.Reason = "NotFound"
		cond.Message = "PlanPolicy not found"
		return cond, nil
	} else {
		cond.Message = fmt.Sprintf("Discovered PlanPolicy %s targeting %s %s", planPolicy.Name, planPolicy.Spec.TargetRef.Kind, planPolicy.Spec.TargetRef.Name)
	}

	return cond, nil
}

func (r *APIProductReconciler) findPlanPolicyForAPIProduct(ctx context.Context, apiProductObj *devportalv1alpha1.APIProduct) (*planpolicyv1alpha1.PlanPolicy, error) {
	route := &gwapiv1.HTTPRoute{}
	rKey := client.ObjectKey{ // Its deployment is built after the same name and namespace
		Namespace: apiProductObj.Namespace,
		Name:      string(apiProductObj.Spec.TargetRef.Name),
	}
	err := r.Get(ctx, rKey, route)
	if client.IgnoreNotFound(err) != nil {
		return nil, err
	}

	if apierrors.IsNotFound(err) {
		return nil, nil
	}

	planPolicies := GetPlanPolicies(ctx)

	if planPolicies == nil {
		// should not happen
		// If it does, check context content
		return nil, errors.New("cannot read plan policies")
	}

	// Look for plan policy targeting the httproute.
	// if not found, try targeting parents

	planPolicy, ok := lo.Find(planPolicies.Items, func(p planpolicyv1alpha1.PlanPolicy) bool {
		return p.Spec.TargetRef.Kind == "HTTPRoute" &&
			p.Namespace == route.Namespace &&
			string(p.Spec.TargetRef.Name) == route.Name
	})

	if ok {
		return &planPolicy, nil
	}

	gatewayPlanPolicies := lo.Filter(planPolicies.Items, func(p planpolicyv1alpha1.PlanPolicy, _ int) bool {
		return p.Spec.TargetRef.Kind == "Gateway"
	})

	planPolicy, ok = lo.Find(gatewayPlanPolicies, func(plan planpolicyv1alpha1.PlanPolicy) bool {
		return lo.ContainsBy(route.Spec.ParentRefs, func(parentRef gwapiv1.ParentReference) bool {
			parentNamespace := ptr.Deref(parentRef.Namespace, gwapiv1.Namespace(route.Namespace))
			return plan.Spec.TargetRef.Name == parentRef.Name &&
				plan.Namespace == string(parentNamespace)
		})
	})

	if ok {
		return &planPolicy, nil
	}

	return nil, nil
}

func (r *APIProductReconciler) openAPIStatus(ctx context.Context, apiProductObj *devportalv1alpha1.APIProduct) (*devportalv1alpha1.OpenAPIStatus, error) {
	logger := logf.FromContext(ctx, "apiproduct", client.ObjectKeyFromObject(apiProductObj))

	// Check if OpenAPI URL is specified
	if apiProductObj.Spec.Documentation == nil || apiProductObj.Spec.Documentation.OpenAPISpecURL == nil {
		logger.V(1).Info("no OpenAPI URL specified, skipping fetch")
		return nil, nil
	}

	// Only fetch if spec has changed (generation mismatch)
	if apiProductObj.Generation == apiProductObj.Status.ObservedGeneration {
		logger.V(1).Info("spec unchanged, returning existing OpenAPI status")
		return apiProductObj.Status.OpenAPI, nil
	}

	// Fetch OpenAPI content
	openAPIURL := *apiProductObj.Spec.Documentation.OpenAPISpecURL
	logger.Info("fetching OpenAPI spec", "url", openAPIURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, openAPIURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request for OpenAPI spec: %w", err)
	}

	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OpenAPI spec from %s: %w", openAPIURL, err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Error(closeErr, "failed to close response body")
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch OpenAPI spec from %s: unexpected status code %d", openAPIURL, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OpenAPI spec response body: %w", err)
	}

	logger.Info("successfully fetched OpenAPI spec", "size", len(body))

	return &devportalv1alpha1.OpenAPIStatus{
		Raw:          string(body),
		LastSyncTime: metav1.Now(),
	}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *APIProductReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Watches(&devportalv1alpha1.APIProduct{}, handler.EnqueueRequestsFromMapFunc(r.enqueueClass)).
		Watches(&planpolicyv1alpha1.PlanPolicy{}, handler.EnqueueRequestsFromMapFunc(r.enqueueClass)).
		Watches(&gwapiv1.HTTPRoute{}, handler.EnqueueRequestsFromMapFunc(r.enqueueClass)).
		Named("apiproduct").
		Complete(r)
}

func (r *APIProductReconciler) enqueueClass(_ context.Context, _ client.Object) []ctrl.Request {
	return []ctrl.Request{{NamespacedName: types.NamespacedName{
		Name: string("apiproduct"),
	}}}
}
