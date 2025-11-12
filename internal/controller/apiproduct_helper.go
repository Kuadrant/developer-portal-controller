package controller

import (
	"context"

	planpolicyv1alpha1 "github.com/kuadrant/kuadrant-operator/cmd/extensions/plan-policy/api/v1alpha1"
)

type planPoliciesCtxKeyType string

const planPoliciesCtxKey planPoliciesCtxKeyType = "plan-policies"

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
