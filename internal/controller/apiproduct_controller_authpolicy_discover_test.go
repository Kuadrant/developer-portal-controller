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
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayapiv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	authorinov1beta3 "github.com/kuadrant/authorino/api/v1beta3"
	kuadrantapiv1 "github.com/kuadrant/kuadrant-operator/api/v1"

	devportalv1alpha1 "github.com/kuadrant/developer-portal-controller/api/v1alpha1"
)

var _ = Describe("APIProduct Controller: AuthPolicy Discovery", func() {
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

	Context("When authpolicy targets httproute", func() {
		const apiProductName = "test-apiproduct-auth"
		const authPolicyName = "test-authpolicy"

		ctx := context.Background()

		var (
			apiProductKey types.NamespacedName
			apiproduct    *devportalv1alpha1.APIProduct
			authPolicy    *kuadrantapiv1.AuthPolicy
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

			authPolicy = &kuadrantapiv1.AuthPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       "AuthPolicy",
					APIVersion: kuadrantapiv1.GroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      authPolicyName,
					Namespace: apiProductKey.Namespace,
				},
				Spec: kuadrantapiv1.AuthPolicySpec{
					TargetRef: gatewayapiv1alpha2.LocalPolicyTargetReferenceWithSectionName{
						LocalPolicyTargetReference: gatewayapiv1alpha2.LocalPolicyTargetReference{
							Group: gwapiv1.GroupName,
							Name:  gwapiv1.ObjectName(TestHTTPRouteName),
							Kind:  "HTTPRoute",
						},
					},
					AuthPolicySpecProper: kuadrantapiv1.AuthPolicySpecProper{
						AuthScheme: &kuadrantapiv1.AuthSchemeSpec{
							Authentication: map[string]kuadrantapiv1.MergeableAuthenticationSpec{
								"api-key": {
									AuthenticationSpec: authorinov1beta3.AuthenticationSpec{
										Credentials: authorinov1beta3.Credentials{
											AuthorizationHeader: &authorinov1beta3.Prefixed{
												Prefix: "APIKEY",
											},
										},
										AuthenticationMethodSpec: authorinov1beta3.AuthenticationMethodSpec{
											ApiKey: &authorinov1beta3.ApiKeyAuthenticationSpec{
												Selector: &metav1.LabelSelector{
													MatchLabels: map[string]string{
														"app": "test-label",
													},
												},
											},
										},
									},
								},
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
			Expect(k8sClient.Create(ctx, authPolicy)).ToNot(HaveOccurred())
			setAcceptedAndEnforcedConditionsToAuthPolicy(authPolicy)
			Expect(k8sClient.Status().Update(ctx, authPolicy)).ToNot(HaveOccurred())
		})

		It("should discover auth scheme from route-targeted authpolicy", func() {
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

			// Check AuthPolicyDiscovered condition
			authPolicyCondition := meta.FindStatusCondition(apiproduct.Status.Conditions, devportalv1alpha1.StatusConditionAuthPolicyDiscovered)
			Expect(authPolicyCondition).NotTo(BeNil())
			Expect(authPolicyCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(authPolicyCondition.Reason).To(Equal("Found"))
			Expect(authPolicyCondition.Message).To(ContainSubstring("HTTPRoute"))

			By("Checking discovered auth scheme")
			Expect(apiproduct.Status.DiscoveredAuthScheme).NotTo(BeNil())
			Expect(apiproduct.Status.DiscoveredAuthScheme.Authentication).To(HaveLen(1))
			Expect(apiproduct.Status.DiscoveredAuthScheme.Authentication).To(HaveKey("api-key"))
			auth := apiproduct.Status.DiscoveredAuthScheme.Authentication["api-key"]
			Expect(auth.AuthenticationSpec.Credentials).To(Equal(authorinov1beta3.Credentials{
				AuthorizationHeader: &authorinov1beta3.Prefixed{
					Prefix: "APIKEY",
				},
			}))
			Expect(auth.AuthenticationSpec.AuthenticationMethodSpec).To(
				Equal(
					authorinov1beta3.AuthenticationMethodSpec{
						ApiKey: &authorinov1beta3.ApiKeyAuthenticationSpec{
							Selector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": "test-label",
								},
							},
						}}))
		})
	})

	Context("When authpolicy targets gateway", func() {
		const apiProductName = "test-apiproduct-auth-gw"
		const authPolicyName = "test-authpolicy-gw"

		ctx := context.Background()

		var (
			apiProductKey types.NamespacedName
			apiproduct    *devportalv1alpha1.APIProduct
			authPolicy    *kuadrantapiv1.AuthPolicy
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

			// AuthPolicy targeting the Gateway instead of HTTPRoute
			authPolicy = &kuadrantapiv1.AuthPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       "AuthPolicy",
					APIVersion: kuadrantapiv1.GroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      authPolicyName,
					Namespace: apiProductKey.Namespace,
				},
				Spec: kuadrantapiv1.AuthPolicySpec{
					TargetRef: gatewayapiv1alpha2.LocalPolicyTargetReferenceWithSectionName{
						LocalPolicyTargetReference: gatewayapiv1alpha2.LocalPolicyTargetReference{
							Group: gwapiv1.GroupName,
							Name:  gwapiv1.ObjectName(TestGatewayName), // Target Gateway, not HTTPRoute
							Kind:  "Gateway",
						},
					},
					AuthPolicySpecProper: kuadrantapiv1.AuthPolicySpecProper{
						AuthScheme: &kuadrantapiv1.AuthSchemeSpec{
							Authentication: map[string]kuadrantapiv1.MergeableAuthenticationSpec{
								"api-key": {
									AuthenticationSpec: authorinov1beta3.AuthenticationSpec{
										Credentials: authorinov1beta3.Credentials{
											AuthorizationHeader: &authorinov1beta3.Prefixed{
												Prefix: "APIKEY",
											},
										},
										AuthenticationMethodSpec: authorinov1beta3.AuthenticationMethodSpec{
											ApiKey: &authorinov1beta3.ApiKeyAuthenticationSpec{
												Selector: &metav1.LabelSelector{
													MatchLabels: map[string]string{
														"app": "test-label",
													},
												},
											},
										},
									},
								},
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
			Expect(k8sClient.Create(ctx, authPolicy)).ToNot(HaveOccurred())
			setAcceptedAndEnforcedConditionsToAuthPolicy(authPolicy)
			Expect(k8sClient.Status().Update(ctx, authPolicy)).ToNot(HaveOccurred())
		})

		It("should discover auth scheme from gateway-targeted authpolicy", func() {
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

			// Check AuthPolicyDiscovered condition
			authPolicyCondition := meta.FindStatusCondition(apiproduct.Status.Conditions, devportalv1alpha1.StatusConditionAuthPolicyDiscovered)
			Expect(authPolicyCondition).NotTo(BeNil())
			Expect(authPolicyCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(authPolicyCondition.Reason).To(Equal("Found"))
			Expect(authPolicyCondition.Message).To(ContainSubstring("Gateway"))

			By("Checking discovered auth scheme from gateway policy")
			Expect(apiproduct.Status.DiscoveredAuthScheme).NotTo(BeNil())
			Expect(apiproduct.Status.DiscoveredAuthScheme.Authentication).To(HaveLen(1))
			Expect(apiproduct.Status.DiscoveredAuthScheme.Authentication).To(HaveKey("api-key"))
			auth := apiproduct.Status.DiscoveredAuthScheme.Authentication["api-key"]
			Expect(auth.AuthenticationSpec.Credentials).To(Equal(authorinov1beta3.Credentials{
				AuthorizationHeader: &authorinov1beta3.Prefixed{
					Prefix: "APIKEY",
				},
			}))
			Expect(auth.AuthenticationSpec.AuthenticationMethodSpec).To(
				Equal(
					authorinov1beta3.AuthenticationMethodSpec{
						ApiKey: &authorinov1beta3.ApiKeyAuthenticationSpec{
							Selector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": "test-label",
								},
							},
						}}))
		})
	})

	Context("When no authpolicy targets httproute or gateway", func() {
		const apiProductName = "test-apiproduct-noauth"
		const testGatewayNameNoAuth = "my-gateway-noauth"
		const testHTTPRouteNameNoAuth = "my-route-noauth"

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
						Name:  testHTTPRouteNameNoAuth,
						Kind:  "HTTPRoute",
					},
					PublishStatus: "Draft",
					ApprovalMode:  "manual",
				},
			}

			// Create Gateway and HTTPRoute but NO AuthPolicy
			gateway = buildBasicGateway(testGatewayNameNoAuth, testNamespace)
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			route = buildBasicHttpRoute(testHTTPRouteNameNoAuth, testGatewayNameNoAuth, testNamespace, []string{"noauth.example.com"})
			Expect(k8sClient.Create(ctx, route)).ToNot(HaveOccurred())
			addAcceptedCondition(route)
			Expect(k8sClient.Status().Update(ctx, route)).ToNot(HaveOccurred())
			Expect(k8sClient.Create(ctx, apiproduct)).ToNot(HaveOccurred())
			// Note: No AuthPolicy is created
		})

		It("should indicate httproute is ready but no authpolicy found", func() {
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

			By("Checking authpolicy condition is false (no authpolicy found)")
			// Check AuthPolicyDiscovered condition is False because no AuthPolicy exists
			authPolicyCondition := meta.FindStatusCondition(apiproduct.Status.Conditions, devportalv1alpha1.StatusConditionAuthPolicyDiscovered)
			Expect(authPolicyCondition).NotTo(BeNil())
			Expect(authPolicyCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(authPolicyCondition.Reason).To(Equal("NotFound"))
			Expect(authPolicyCondition.Message).To(Equal("AuthPolicy not found"))

			By("Checking no auth scheme is discovered")
			Expect(apiproduct.Status.DiscoveredAuthScheme).To(BeNil())
		})
	})

	Context("When the authpolicy is not accepted", func() {
		const apiProductName = "test-apiproduct-auth"
		const authPolicyName = "test-authpolicy"

		ctx := context.Background()

		var (
			apiProductKey types.NamespacedName
			apiproduct    *devportalv1alpha1.APIProduct
			authPolicy    *kuadrantapiv1.AuthPolicy
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

			authPolicy = &kuadrantapiv1.AuthPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       "AuthPolicy",
					APIVersion: kuadrantapiv1.GroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      authPolicyName,
					Namespace: apiProductKey.Namespace,
				},
				Spec: kuadrantapiv1.AuthPolicySpec{
					TargetRef: gatewayapiv1alpha2.LocalPolicyTargetReferenceWithSectionName{
						LocalPolicyTargetReference: gatewayapiv1alpha2.LocalPolicyTargetReference{
							Group: gwapiv1.GroupName,
							Name:  gwapiv1.ObjectName(TestHTTPRouteName),
							Kind:  "HTTPRoute",
						},
					},
					AuthPolicySpecProper: kuadrantapiv1.AuthPolicySpecProper{
						AuthScheme: &kuadrantapiv1.AuthSchemeSpec{
							Authentication: map[string]kuadrantapiv1.MergeableAuthenticationSpec{
								"api-key": {
									AuthenticationSpec: authorinov1beta3.AuthenticationSpec{
										Credentials: authorinov1beta3.Credentials{
											AuthorizationHeader: &authorinov1beta3.Prefixed{
												Prefix: "APIKEY",
											},
										},
										AuthenticationMethodSpec: authorinov1beta3.AuthenticationMethodSpec{
											ApiKey: &authorinov1beta3.ApiKeyAuthenticationSpec{
												Selector: &metav1.LabelSelector{
													MatchLabels: map[string]string{
														"app": "test-label",
													},
												},
											},
										},
									},
								},
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
			Expect(k8sClient.Create(ctx, authPolicy)).ToNot(HaveOccurred())
			setNotAcceptedConditionToAuthPolicy(authPolicy)
			Expect(k8sClient.Status().Update(ctx, authPolicy)).ToNot(HaveOccurred())
		})

		It("should not discover auth scheme", func() {
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

			// Check AuthPolicyDiscovered condition
			authPolicyCondition := meta.FindStatusCondition(apiproduct.Status.Conditions, devportalv1alpha1.StatusConditionAuthPolicyDiscovered)
			Expect(authPolicyCondition).NotTo(BeNil())
			Expect(authPolicyCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(authPolicyCondition.Reason).To(Equal("AuthPolicyNotReady"))
			Expect(apiproduct.Status.DiscoveredAuthScheme).To(BeNil())
		})
	})
})
