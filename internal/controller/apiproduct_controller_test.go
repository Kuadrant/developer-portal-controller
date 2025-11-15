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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayapiv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	planpolicyv1alpha1 "github.com/kuadrant/kuadrant-operator/cmd/extensions/plan-policy/api/v1alpha1"

	devportalv1alpha1 "github.com/kuadrant/developer-portal-controller/api/v1alpha1"
)

var _ = Describe("APIProduct Controller", func() {
	const (
		nodeTimeOut       = NodeTimeout(time.Second * 30)
		TestGatewayName   = "my-gateway"
		TestHTTPRouteName = "my-route"
	)
	var (
		testNamespace string
		gateway       *gwapiv1.Gateway
		route         *gwapiv1.HTTPRoute
	)

	BeforeEach(func(ctx SpecContext) {
		createNamespaceWithContext(ctx, &testNamespace)
	})

	AfterEach(func(ctx SpecContext) {
		deleteNamespaceWithContext(ctx, &testNamespace)
	}, nodeTimeOut)

	Context("When planpolicy targets httproute", func() {
		const apiProductName = "test-apiproduct"
		const planPolicyName = "test-planpolicy"

		ctx := context.Background()

		var (
			apiProductKey types.NamespacedName
			apiproduct    *devportalv1alpha1.APIProduct
			planPolicy    *planpolicyv1alpha1.PlanPolicy
		)

		BeforeEach(func() {
			// Create namespace-dependent objects after namespace is created
			apiProductKey = types.NamespacedName{
				Name:      apiProductName,
				Namespace: testNamespace,
			}
			apiproduct = &devportalv1alpha1.APIProduct{
				TypeMeta: metav1.TypeMeta{
					Kind:       "APIProduct",
					APIVersion: devportalv1alpha1.GroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiProductKey.Name,
					Namespace: apiProductKey.Namespace,
				},
				Spec: devportalv1alpha1.APIProductSpec{
					TargetRef: gatewayapiv1alpha2.LocalPolicyTargetReference{
						Group: gwapiv1.GroupName,
						Name:  TestHTTPRouteName,
						Kind:  "HTTPRoute",
					},
					PublishStatus: "Draft",
					ApprovalMode:  "manual",
				},
			}

			planPolicy = &planpolicyv1alpha1.PlanPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       "PlanPolicy",
					APIVersion: planpolicyv1alpha1.GroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      planPolicyName,
					Namespace: apiProductKey.Namespace,
				},
				Spec: planpolicyv1alpha1.PlanPolicySpec{
					TargetRef: gatewayapiv1alpha2.LocalPolicyTargetReferenceWithSectionName{
						LocalPolicyTargetReference: gatewayapiv1alpha2.LocalPolicyTargetReference{
							Group: gwapiv1.GroupName,
							Name:  gwapiv1.ObjectName(TestHTTPRouteName),
							Kind:  "HTTPRoute",
						},
					},
					Plans: []planpolicyv1alpha1.Plan{
						{
							Tier:      "gold",
							Predicate: "auth.identity.tier == 'gold'",
							Limits: planpolicyv1alpha1.Limits{
								Daily: ptr.To(10000),
							},
						},
						{
							Tier:      "silver",
							Predicate: "auth.identity.tier == 'silver'",
							Limits: planpolicyv1alpha1.Limits{
								Daily: ptr.To(1000),
							},
						},
					},
				},
			}

			gateway = buildBasicGateway(TestGatewayName, testNamespace)
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			route = buildBasicHttpRoute(TestHTTPRouteName, TestGatewayName, testNamespace, []string{"example.com"})
			Expect(k8sClient.Create(ctx, route)).ToNot(HaveOccurred())
			addAcceptedCondition(route)
			Expect(k8sClient.Status().Update(ctx, route)).ToNot(HaveOccurred())
			Expect(k8sClient.Create(ctx, apiproduct)).ToNot(HaveOccurred())
			Expect(k8sClient.Create(ctx, planPolicy)).ToNot(HaveOccurred())
		})

		It("should discover plans from route-targeted planpolicy", func() {
			By("Reconciling the created resource")
			controllerReconciler := &APIProductReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			err = k8sClient.Get(ctx, apiProductKey, apiproduct)
			Expect(err).NotTo(HaveOccurred())

			By("Checking status conditions")
			// Check Ready condition
			readyCondition := meta.FindStatusCondition(apiproduct.Status.Conditions, devportalv1alpha1.StatusConditionReady)
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(readyCondition.Reason).To(Equal("HTTPRouteAccepted"))

			// Check PlanPolicyDiscovered condition
			planPolicyCondition := meta.FindStatusCondition(apiproduct.Status.Conditions, devportalv1alpha1.StatusConditionPlanPolicyDiscovered)
			Expect(planPolicyCondition).NotTo(BeNil())
			Expect(planPolicyCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(planPolicyCondition.Reason).To(Equal("Found"))
			Expect(planPolicyCondition.Message).To(ContainSubstring("HTTPRoute"))

			By("Checking discovered plans")
			Expect(apiproduct.Status.DiscoveredPlans).To(HaveLen(2))

			// Check gold plan
			goldPlan := apiproduct.Status.DiscoveredPlans[0]
			Expect(goldPlan.Tier).To(Equal("gold"))
			Expect(goldPlan.Limits.Daily).NotTo(BeNil())
			Expect(*goldPlan.Limits.Daily).To(Equal(10000))

			// Check silver plan
			silverPlan := apiproduct.Status.DiscoveredPlans[1]
			Expect(silverPlan.Tier).To(Equal("silver"))
			Expect(silverPlan.Limits.Daily).NotTo(BeNil())
			Expect(*silverPlan.Limits.Daily).To(Equal(1000))
		})
	})

	Context("When planpolicy targets gateway", func() {
		const apiProductName = "test-apiproduct-gw"
		const planPolicyName = "test-planpolicy-gw"

		ctx := context.Background()

		var (
			apiProductKey types.NamespacedName
			apiproduct    *devportalv1alpha1.APIProduct
			planPolicy    *planpolicyv1alpha1.PlanPolicy
		)

		BeforeEach(func() {
			// Create namespace-dependent objects after namespace is created
			apiProductKey = types.NamespacedName{
				Name:      apiProductName,
				Namespace: testNamespace,
			}
			apiproduct = &devportalv1alpha1.APIProduct{
				TypeMeta: metav1.TypeMeta{
					Kind:       "APIProduct",
					APIVersion: devportalv1alpha1.GroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiProductKey.Name,
					Namespace: apiProductKey.Namespace,
				},
				Spec: devportalv1alpha1.APIProductSpec{
					TargetRef: gatewayapiv1alpha2.LocalPolicyTargetReference{
						Group: gwapiv1.GroupName,
						Name:  TestHTTPRouteName,
						Kind:  "HTTPRoute",
					},
					PublishStatus: "Draft",
					ApprovalMode:  "manual",
				},
			}

			// PlanPolicy targeting the Gateway instead of HTTPRoute
			planPolicy = &planpolicyv1alpha1.PlanPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       "PlanPolicy",
					APIVersion: planpolicyv1alpha1.GroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      planPolicyName,
					Namespace: apiProductKey.Namespace,
				},
				Spec: planpolicyv1alpha1.PlanPolicySpec{
					TargetRef: gatewayapiv1alpha2.LocalPolicyTargetReferenceWithSectionName{
						LocalPolicyTargetReference: gatewayapiv1alpha2.LocalPolicyTargetReference{
							Group: gwapiv1.GroupName,
							Name:  gwapiv1.ObjectName(TestGatewayName), // Target Gateway, not HTTPRoute
							Kind:  "Gateway",
						},
					},
					Plans: []planpolicyv1alpha1.Plan{
						{
							Tier:      "premium",
							Predicate: "auth.identity.tier == 'premium'",
							Limits: planpolicyv1alpha1.Limits{
								Daily: ptr.To(50000),
							},
						},
						{
							Tier:      "basic",
							Predicate: "auth.identity.tier == 'basic'",
							Limits: planpolicyv1alpha1.Limits{
								Daily: ptr.To(100),
							},
						},
					},
				},
			}

			gateway = buildBasicGateway(TestGatewayName, testNamespace)
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			route = buildBasicHttpRoute(TestHTTPRouteName, TestGatewayName, testNamespace, []string{"api.example.com"})
			Expect(k8sClient.Create(ctx, route)).ToNot(HaveOccurred())
			addAcceptedCondition(route)
			Expect(k8sClient.Status().Update(ctx, route)).ToNot(HaveOccurred())
			Expect(k8sClient.Create(ctx, apiproduct)).ToNot(HaveOccurred())
			Expect(k8sClient.Create(ctx, planPolicy)).ToNot(HaveOccurred())
		})

		It("should discover plans from gateway-targeted planpolicy", func() {
			By("Reconciling the created resource")
			controllerReconciler := &APIProductReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			err = k8sClient.Get(ctx, apiProductKey, apiproduct)
			Expect(err).NotTo(HaveOccurred())

			By("Checking status conditions")
			// Check Ready condition
			readyCondition := meta.FindStatusCondition(apiproduct.Status.Conditions, devportalv1alpha1.StatusConditionReady)
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(readyCondition.Reason).To(Equal("HTTPRouteAccepted"))

			// Check PlanPolicyDiscovered condition
			planPolicyCondition := meta.FindStatusCondition(apiproduct.Status.Conditions, devportalv1alpha1.StatusConditionPlanPolicyDiscovered)
			Expect(planPolicyCondition).NotTo(BeNil())
			Expect(planPolicyCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(planPolicyCondition.Reason).To(Equal("Found"))
			Expect(planPolicyCondition.Message).To(ContainSubstring("Gateway"))

			By("Checking discovered plans from gateway policy")
			Expect(apiproduct.Status.DiscoveredPlans).To(HaveLen(2))

			// Check premium plan
			premiumPlan := apiproduct.Status.DiscoveredPlans[0]
			Expect(premiumPlan.Tier).To(Equal("premium"))
			Expect(premiumPlan.Limits.Daily).NotTo(BeNil())
			Expect(*premiumPlan.Limits.Daily).To(Equal(50000))

			// Check basic plan
			basicPlan := apiproduct.Status.DiscoveredPlans[1]
			Expect(basicPlan.Tier).To(Equal("basic"))
			Expect(basicPlan.Limits.Daily).NotTo(BeNil())
			Expect(*basicPlan.Limits.Daily).To(Equal(100))
		})
	})

	Context("When apiproduct targets non-existing httproute", func() {
		const apiProductName = "test-apiproduct-notfound"
		const nonExistingRouteName = "non-existing-route"

		ctx := context.Background()

		var (
			apiProductKey types.NamespacedName
			apiproduct    *devportalv1alpha1.APIProduct
		)

		BeforeEach(func() {
			// Create APIProduct targeting a non-existing HTTPRoute
			apiProductKey = types.NamespacedName{
				Name:      apiProductName,
				Namespace: testNamespace,
			}
			apiproduct = &devportalv1alpha1.APIProduct{
				TypeMeta: metav1.TypeMeta{
					Kind:       "APIProduct",
					APIVersion: devportalv1alpha1.GroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiProductKey.Name,
					Namespace: apiProductKey.Namespace,
				},
				Spec: devportalv1alpha1.APIProductSpec{
					TargetRef: gatewayapiv1alpha2.LocalPolicyTargetReference{
						Group: gwapiv1.GroupName,
						Name:  nonExistingRouteName,
						Kind:  "HTTPRoute",
					},
					PublishStatus: "Draft",
					ApprovalMode:  "manual",
				},
			}

			Expect(k8sClient.Create(ctx, apiproduct)).ToNot(HaveOccurred())
		})

		It("should set ready condition to false when httproute not found", func() {
			By("Reconciling the created resource")
			controllerReconciler := &APIProductReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			err = k8sClient.Get(ctx, apiProductKey, apiproduct)
			Expect(err).NotTo(HaveOccurred())

			By("Checking status conditions reflect httproute not found")
			// Check Ready condition is False
			readyCondition := meta.FindStatusCondition(apiproduct.Status.Conditions, devportalv1alpha1.StatusConditionReady)
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(readyCondition.Reason).To(Equal("HTTPRouteNotFound"))
			Expect(readyCondition.Message).To(ContainSubstring(nonExistingRouteName))

			// Check PlanPolicyDiscovered condition is False
			planPolicyCondition := meta.FindStatusCondition(apiproduct.Status.Conditions, devportalv1alpha1.StatusConditionPlanPolicyDiscovered)
			Expect(planPolicyCondition).NotTo(BeNil())
			Expect(planPolicyCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(planPolicyCondition.Reason).To(Equal("NotFound"))

			By("Checking no plans are discovered")
			Expect(apiproduct.Status.DiscoveredPlans).To(BeEmpty())
		})
	})

	Context("When no planpolicy targets httproute or gateway", func() {
		const apiProductName = "test-apiproduct-noplan"
		const testGatewayNameNoPlan = "my-gateway-noplan"
		const testHTTPRouteNameNoPlan = "my-route-noplan"

		ctx := context.Background()

		var (
			apiProductKey types.NamespacedName
			apiproduct    *devportalv1alpha1.APIProduct
		)

		BeforeEach(func() {
			// Create namespace-dependent objects after namespace is created
			apiProductKey = types.NamespacedName{
				Name:      apiProductName,
				Namespace: testNamespace,
			}
			apiproduct = &devportalv1alpha1.APIProduct{
				TypeMeta: metav1.TypeMeta{
					Kind:       "APIProduct",
					APIVersion: devportalv1alpha1.GroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiProductKey.Name,
					Namespace: apiProductKey.Namespace,
				},
				Spec: devportalv1alpha1.APIProductSpec{
					TargetRef: gatewayapiv1alpha2.LocalPolicyTargetReference{
						Group: gwapiv1.GroupName,
						Name:  testHTTPRouteNameNoPlan,
						Kind:  "HTTPRoute",
					},
					PublishStatus: "Draft",
					ApprovalMode:  "manual",
				},
			}

			// Create Gateway and HTTPRoute but NO PlanPolicy
			gateway = buildBasicGateway(testGatewayNameNoPlan, testNamespace)
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			route = buildBasicHttpRoute(testHTTPRouteNameNoPlan, testGatewayNameNoPlan, testNamespace, []string{"noplan.example.com"})
			Expect(k8sClient.Create(ctx, route)).ToNot(HaveOccurred())
			addAcceptedCondition(route)
			Expect(k8sClient.Status().Update(ctx, route)).ToNot(HaveOccurred())
			Expect(k8sClient.Create(ctx, apiproduct)).ToNot(HaveOccurred())
			// Note: No PlanPolicy is created
		})

		It("should indicate httproute is ready but no planpolicy found", func() {
			By("Reconciling the created resource")
			controllerReconciler := &APIProductReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			err = k8sClient.Get(ctx, apiProductKey, apiproduct)
			Expect(err).NotTo(HaveOccurred())

			By("Checking ready condition is true (httproute exists and is accepted)")
			// Check Ready condition is True because HTTPRoute exists and is accepted
			readyCondition := meta.FindStatusCondition(apiproduct.Status.Conditions, devportalv1alpha1.StatusConditionReady)
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(readyCondition.Reason).To(Equal("HTTPRouteAccepted"))

			By("Checking planpolicy condition is false (no planpolicy found)")
			// Check PlanPolicyDiscovered condition is False because no PlanPolicy exists
			planPolicyCondition := meta.FindStatusCondition(apiproduct.Status.Conditions, devportalv1alpha1.StatusConditionPlanPolicyDiscovered)
			Expect(planPolicyCondition).NotTo(BeNil())
			Expect(planPolicyCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(planPolicyCondition.Reason).To(Equal("NotFound"))
			Expect(planPolicyCondition.Message).To(Equal("PlanPolicy not found"))

			By("Checking no plans are discovered")
			Expect(apiproduct.Status.DiscoveredPlans).To(BeEmpty())
		})
	})

	Context("When httproute is not accepted", func() {
		const apiProductName = "test-apiproduct-notaccepted"
		const planPolicyName = "test-planpolicy-notaccepted"
		const testGatewayNameNotAccepted = "my-gateway-notaccepted"
		const testHTTPRouteNameNotAccepted = "my-route-notaccepted"

		ctx := context.Background()

		var (
			apiProductKey types.NamespacedName
			apiproduct    *devportalv1alpha1.APIProduct
			planPolicy    *planpolicyv1alpha1.PlanPolicy
		)

		BeforeEach(func() {
			// Create namespace-dependent objects after namespace is created
			apiProductKey = types.NamespacedName{
				Name:      apiProductName,
				Namespace: testNamespace,
			}
			apiproduct = &devportalv1alpha1.APIProduct{
				TypeMeta: metav1.TypeMeta{
					Kind:       "APIProduct",
					APIVersion: devportalv1alpha1.GroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiProductKey.Name,
					Namespace: apiProductKey.Namespace,
				},
				Spec: devportalv1alpha1.APIProductSpec{
					TargetRef: gatewayapiv1alpha2.LocalPolicyTargetReference{
						Group: gwapiv1.GroupName,
						Name:  testHTTPRouteNameNotAccepted,
						Kind:  "HTTPRoute",
					},
					PublishStatus: "Draft",
					ApprovalMode:  "manual",
				},
			}

			planPolicy = &planpolicyv1alpha1.PlanPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       "PlanPolicy",
					APIVersion: planpolicyv1alpha1.GroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      planPolicyName,
					Namespace: apiProductKey.Namespace,
				},
				Spec: planpolicyv1alpha1.PlanPolicySpec{
					TargetRef: gatewayapiv1alpha2.LocalPolicyTargetReferenceWithSectionName{
						LocalPolicyTargetReference: gatewayapiv1alpha2.LocalPolicyTargetReference{
							Group: gwapiv1.GroupName,
							Name:  gwapiv1.ObjectName(testHTTPRouteNameNotAccepted),
							Kind:  "HTTPRoute",
						},
					},
					Plans: []planpolicyv1alpha1.Plan{
						{
							Tier:      "enterprise",
							Predicate: "auth.identity.tier == 'enterprise'",
							Limits: planpolicyv1alpha1.Limits{
								Daily: ptr.To(100000),
							},
						},
					},
				},
			}

			gateway = buildBasicGateway(testGatewayNameNotAccepted, testNamespace)
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			route = buildBasicHttpRoute(testHTTPRouteNameNotAccepted, testGatewayNameNotAccepted, testNamespace, []string{"notaccepted.example.com"})
			Expect(k8sClient.Create(ctx, route)).ToNot(HaveOccurred())

			// Set HTTPRoute status with accepted condition = False
			addNotAcceptedCondition(route)
			Expect(k8sClient.Status().Update(ctx, route)).ToNot(HaveOccurred())

			Expect(k8sClient.Create(ctx, apiproduct)).ToNot(HaveOccurred())
			Expect(k8sClient.Create(ctx, planPolicy)).ToNot(HaveOccurred())
		})

		It("should set ready condition to false when httproute is not accepted", func() {
			By("Reconciling the created resource")
			controllerReconciler := &APIProductReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			err = k8sClient.Get(ctx, apiProductKey, apiproduct)
			Expect(err).NotTo(HaveOccurred())

			By("Checking ready condition is false (httproute not accepted)")
			// Check Ready condition is False because HTTPRoute is not accepted
			readyCondition := meta.FindStatusCondition(apiproduct.Status.Conditions, devportalv1alpha1.StatusConditionReady)
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(readyCondition.Reason).To(Equal("HTTPRouteNotAccepted"))

			By("Checking planpolicy is still discovered")
			// PlanPolicy can still be discovered even if HTTPRoute is not accepted
			planPolicyCondition := meta.FindStatusCondition(apiproduct.Status.Conditions, devportalv1alpha1.StatusConditionPlanPolicyDiscovered)
			Expect(planPolicyCondition).NotTo(BeNil())
			Expect(planPolicyCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(planPolicyCondition.Reason).To(Equal("Found"))

			By("Checking plans are discovered despite httproute not being accepted")
			// Plans should still be discovered from the PlanPolicy
			Expect(apiproduct.Status.DiscoveredPlans).To(HaveLen(1))
			enterprisePlan := apiproduct.Status.DiscoveredPlans[0]
			Expect(enterprisePlan.Tier).To(Equal("enterprise"))
			Expect(enterprisePlan.Limits.Daily).NotTo(BeNil())
			Expect(*enterprisePlan.Limits.Daily).To(Equal(100000))
		})
	})
})
