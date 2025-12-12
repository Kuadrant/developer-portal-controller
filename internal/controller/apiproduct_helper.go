package controller

import (
	"context"

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
