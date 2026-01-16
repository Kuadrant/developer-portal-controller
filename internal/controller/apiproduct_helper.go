package controller

import (
	"context"
	"errors"

	"github.com/kuadrant/developer-portal-controller/api/v1alpha1"
	"github.com/samber/lo"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	v1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayapiv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	kuadrantapiv1 "github.com/kuadrant/kuadrant-operator/api/v1"
	planpolicyv1alpha1 "github.com/kuadrant/kuadrant-operator/cmd/extensions/plan-policy/api/v1alpha1"
)

type planPoliciesCtxKeyType string
type authPoliciesCtxKeyType string

const planPoliciesCtxKey planPoliciesCtxKeyType = "plan-policies"
const authPoliciesCtxKey authPoliciesCtxKeyType = "auth-policies"

func WithPlanPolicies(ctx context.Context, planPolicies *planpolicyv1alpha1.PlanPolicyList) context.Context {
	return context.WithValue(ctx, planPoliciesCtxKey, planPolicies)
}

func GetPlanPolicies(ctx context.Context) *planpolicyv1alpha1.PlanPolicyList {
	plans, ok := ctx.Value(planPoliciesCtxKey).(*planpolicyv1alpha1.PlanPolicyList)
	if !ok {
		return nil
	}
	return plans
}

func WithAuthPolicies(ctx context.Context, authPolicies *kuadrantapiv1.AuthPolicyList) context.Context {
	return context.WithValue(ctx, authPoliciesCtxKey, authPolicies)
}

func GetAuthPolicies(ctx context.Context) *kuadrantapiv1.AuthPolicyList {
	authPolicies, ok := ctx.Value(authPoliciesCtxKey).(*kuadrantapiv1.AuthPolicyList)
	if !ok {
		return nil
	}
	return authPolicies
}

func IsAuthPolicyAcceptedAndEnforced(policy *kuadrantapiv1.AuthPolicy) bool {
	return IsAuthPolicyAccepted(policy) && IsAuthPolicyEnforced(policy)
}

func IsAuthPolicyAccepted(policy *kuadrantapiv1.AuthPolicy) bool {
	return IsAuthPolicyConditionTrue(policy, string(gatewayapiv1alpha2.PolicyConditionAccepted))
}

func IsAuthPolicyEnforced(policy *kuadrantapiv1.AuthPolicy) bool {
	return IsAuthPolicyConditionTrue(policy, "Enforced")
}

func IsAuthPolicyConditionTrue(policy *kuadrantapiv1.AuthPolicy, condition string) bool {
	if policy == nil {
		return false
	}

	return meta.IsStatusConditionTrue(policy.Status.Conditions, condition)
}

func FindAuthPolicyForAPIProduct(ctx context.Context, cli client.Client, apiProductObj *v1alpha1.APIProduct) (*kuadrantapiv1.AuthPolicy, error) {
	route := &v1.HTTPRoute{}
	rKey := client.ObjectKey{ // Its deployment is built after the same name and namespace
		Namespace: apiProductObj.Namespace,
		Name:      string(apiProductObj.Spec.TargetRef.Name),
	}

	err := cli.Get(ctx, rKey, route)
	if client.IgnoreNotFound(err) != nil {
		return nil, err
	}

	if apierrors.IsNotFound(err) {
		return nil, nil
	}

	authPolicies := GetAuthPolicies(ctx)

	if authPolicies == nil {
		// should not happen
		// If it does, check context content
		return nil, errors.New("cannot read auth policies")
	}

	// Look for auth policy targeting the httproute.
	// if not found, try targeting parents

	authPolicy, ok := lo.Find(authPolicies.Items, func(p kuadrantapiv1.AuthPolicy) bool {
		return p.Spec.TargetRef.Kind == "HTTPRoute" &&
			p.Namespace == route.Namespace &&
			string(p.Spec.TargetRef.Name) == route.Name
	})

	if ok {
		return &authPolicy, nil
	}

	gatewayAuthPolicies := lo.Filter(authPolicies.Items, func(p kuadrantapiv1.AuthPolicy, _ int) bool {
		return p.Spec.TargetRef.Kind == "Gateway"
	})

	authPolicy, ok = lo.Find(gatewayAuthPolicies, func(authPolicy kuadrantapiv1.AuthPolicy) bool {
		return lo.ContainsBy(route.Spec.ParentRefs, func(parentRef v1.ParentReference) bool {
			parentNamespace := ptr.Deref(parentRef.Namespace, v1.Namespace(route.Namespace))
			return authPolicy.Spec.TargetRef.Name == parentRef.Name &&
				authPolicy.Namespace == string(parentNamespace)
		})
	})

	if ok {
		return &authPolicy, nil
	}

	return nil, nil
}
