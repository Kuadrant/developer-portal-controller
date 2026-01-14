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
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
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

var _ = Describe("APIProduct Controller: OIDC Discovery", func() {
	const (
		nodeTimeOut       = NodeTimeout(time.Second * 30)
		TestGatewayName   = "oidc-gateway"
		TestHTTPRouteName = "oidc-route"
		TestIssuerURL     = "http://keycloak.example.com/realms/test"
		TestTokenEndpoint = "http://keycloak.example.com/realms/test/protocol/openid-connect/token"
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

	Context("When authpolicy has JWT authentication", func() {
		const apiProductName = "test-apiproduct-oidc"
		const authPolicyName = "test-authpolicy-jwt"

		ctx := context.Background()

		var (
			apiProductKey types.NamespacedName
			apiproduct    *devportalv1alpha1.APIProduct
			authPolicy    *kuadrantapiv1.AuthPolicy
		)

		BeforeEach(func() {
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
								"keycloak-jwt": {
									AuthenticationSpec: authorinov1beta3.AuthenticationSpec{
										AuthenticationMethodSpec: authorinov1beta3.AuthenticationMethodSpec{
											Jwt: &authorinov1beta3.JwtAuthenticationSpec{
												IssuerUrl: TestIssuerURL,
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
			route = buildBasicHttpRoute(TestHTTPRouteName, TestGatewayName, testNamespace, []string{"oidc.example.com"})
			Expect(k8sClient.Create(ctx, route)).ToNot(HaveOccurred())
			addAcceptedCondition(route)
			Expect(k8sClient.Status().Update(ctx, route)).ToNot(HaveOccurred())
			Expect(k8sClient.Create(ctx, apiproduct)).ToNot(HaveOccurred())
			Expect(k8sClient.Create(ctx, authPolicy)).ToNot(HaveOccurred())
			setAcceptedAndEnforcedConditionsToAuthPolicy(authPolicy)
			Expect(k8sClient.Status().Update(ctx, authPolicy)).ToNot(HaveOccurred())
		})

		It("should discover OIDC token endpoint", func() {
			By("Setting up mock HTTP client for OIDC discovery")
			mockClient := &mockHTTPClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					Expect(req.URL.String()).To(ContainSubstring(".well-known/openid-configuration"))
					return &http.Response{
						StatusCode: http.StatusOK,
						Body: io.NopCloser(bytes.NewBufferString(`{
							"issuer": "` + TestIssuerURL + `",
							"token_endpoint": "` + TestTokenEndpoint + `"
						}`)),
					}, nil
				},
			}

			By("Reconciling the created resource")
			controllerReconciler := &APIProductReconciler{
				Client:     k8sClient,
				Scheme:     k8sClient.Scheme(),
				HTTPClient: mockClient,
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			err = k8sClient.Get(ctx, apiProductKey, apiproduct)
			Expect(err).NotTo(HaveOccurred())

			By("Checking OIDCDiscovered condition is True")
			oidcCondition := meta.FindStatusCondition(apiproduct.Status.Conditions, devportalv1alpha1.StatusConditionOIDCDiscovered)
			Expect(oidcCondition).NotTo(BeNil())
			Expect(oidcCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(oidcCondition.Reason).To(Equal("Discovered"))
			Expect(oidcCondition.Message).To(ContainSubstring(TestIssuerURL))

			By("Checking OIDCDiscovery status contains token endpoint")
			Expect(apiproduct.Status.OIDCDiscovery).NotTo(BeNil())
			Expect(apiproduct.Status.OIDCDiscovery.TokenEndpoint).To(Equal(TestTokenEndpoint))
		})
	})

	Context("When authpolicy has no JWT authentication", func() {
		const apiProductName = "test-apiproduct-nooidc"
		const authPolicyName = "test-authpolicy-apikey"

		ctx := context.Background()

		var (
			apiProductKey types.NamespacedName
			apiproduct    *devportalv1alpha1.APIProduct
			authPolicy    *kuadrantapiv1.AuthPolicy
		)

		BeforeEach(func() {
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

			// AuthPolicy with API key auth (no JWT)
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
			route = buildBasicHttpRoute(TestHTTPRouteName, TestGatewayName, testNamespace, []string{"nooidc.example.com"})
			Expect(k8sClient.Create(ctx, route)).ToNot(HaveOccurred())
			addAcceptedCondition(route)
			Expect(k8sClient.Status().Update(ctx, route)).ToNot(HaveOccurred())
			Expect(k8sClient.Create(ctx, apiproduct)).ToNot(HaveOccurred())
			Expect(k8sClient.Create(ctx, authPolicy)).ToNot(HaveOccurred())
			setAcceptedAndEnforcedConditionsToAuthPolicy(authPolicy)
			Expect(k8sClient.Status().Update(ctx, authPolicy)).ToNot(HaveOccurred())
		})

		It("should indicate no OIDC auth configured", func() {
			By("Reconciling the created resource")
			mockClient := &mockHTTPClient{}
			controllerReconciler := &APIProductReconciler{
				Client:     k8sClient,
				Scheme:     k8sClient.Scheme(),
				HTTPClient: mockClient,
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			err = k8sClient.Get(ctx, apiProductKey, apiproduct)
			Expect(err).NotTo(HaveOccurred())

			By("Checking OIDCDiscovered condition is False with NoOIDCAuth reason")
			oidcCondition := meta.FindStatusCondition(apiproduct.Status.Conditions, devportalv1alpha1.StatusConditionOIDCDiscovered)
			Expect(oidcCondition).NotTo(BeNil())
			Expect(oidcCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(oidcCondition.Reason).To(Equal("NoOIDCAuth"))

			By("Checking OIDCDiscovery status is nil")
			Expect(apiproduct.Status.OIDCDiscovery).To(BeNil())
		})
	})

	Context("When OIDC discovery HTTP request fails", func() {
		const apiProductName = "test-apiproduct-oidc-fail"
		const authPolicyName = "test-authpolicy-jwt-fail"

		ctx := context.Background()

		var (
			apiProductKey types.NamespacedName
			apiproduct    *devportalv1alpha1.APIProduct
			authPolicy    *kuadrantapiv1.AuthPolicy
		)

		BeforeEach(func() {
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
								"keycloak-jwt": {
									AuthenticationSpec: authorinov1beta3.AuthenticationSpec{
										AuthenticationMethodSpec: authorinov1beta3.AuthenticationMethodSpec{
											Jwt: &authorinov1beta3.JwtAuthenticationSpec{
												IssuerUrl: TestIssuerURL,
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
			route = buildBasicHttpRoute(TestHTTPRouteName, TestGatewayName, testNamespace, []string{"fail.example.com"})
			Expect(k8sClient.Create(ctx, route)).ToNot(HaveOccurred())
			addAcceptedCondition(route)
			Expect(k8sClient.Status().Update(ctx, route)).ToNot(HaveOccurred())
			Expect(k8sClient.Create(ctx, apiproduct)).ToNot(HaveOccurred())
			Expect(k8sClient.Create(ctx, authPolicy)).ToNot(HaveOccurred())
			setAcceptedAndEnforcedConditionsToAuthPolicy(authPolicy)
			Expect(k8sClient.Status().Update(ctx, authPolicy)).ToNot(HaveOccurred())
		})

		It("should indicate OIDC discovery failed", func() {
			By("Setting up mock HTTP client that returns error")
			mockClient := &mockHTTPClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					return nil, errors.New("connection refused")
				},
			}

			By("Reconciling the created resource")
			controllerReconciler := &APIProductReconciler{
				Client:     k8sClient,
				Scheme:     k8sClient.Scheme(),
				HTTPClient: mockClient,
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			err = k8sClient.Get(ctx, apiProductKey, apiproduct)
			Expect(err).NotTo(HaveOccurred())

			By("Checking OIDCDiscovered condition is False with DiscoveryFailed reason")
			oidcCondition := meta.FindStatusCondition(apiproduct.Status.Conditions, devportalv1alpha1.StatusConditionOIDCDiscovered)
			Expect(oidcCondition).NotTo(BeNil())
			Expect(oidcCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(oidcCondition.Reason).To(Equal("DiscoveryFailed"))
			Expect(oidcCondition.Message).To(ContainSubstring("connection refused"))

			By("Checking OIDCDiscovery status is nil")
			Expect(apiproduct.Status.OIDCDiscovery).To(BeNil())
		})
	})

	Context("When OIDC discovery is cached", func() {
		const apiProductName = "test-apiproduct-oidc-cached"
		const authPolicyName = "test-authpolicy-jwt-cached"
		const CachedTokenEndpoint = "http://cached.example.com/token"

		ctx := context.Background()

		var (
			apiProductKey types.NamespacedName
			apiproduct    *devportalv1alpha1.APIProduct
			authPolicy    *kuadrantapiv1.AuthPolicy
		)

		BeforeEach(func() {
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
								"keycloak-jwt": {
									AuthenticationSpec: authorinov1beta3.AuthenticationSpec{
										AuthenticationMethodSpec: authorinov1beta3.AuthenticationMethodSpec{
											Jwt: &authorinov1beta3.JwtAuthenticationSpec{
												IssuerUrl: TestIssuerURL,
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
			route = buildBasicHttpRoute(TestHTTPRouteName, TestGatewayName, testNamespace, []string{"cached.example.com"})
			Expect(k8sClient.Create(ctx, route)).ToNot(HaveOccurred())
			addAcceptedCondition(route)
			Expect(k8sClient.Status().Update(ctx, route)).ToNot(HaveOccurred())
			Expect(k8sClient.Create(ctx, apiproduct)).ToNot(HaveOccurred())
			Expect(k8sClient.Create(ctx, authPolicy)).ToNot(HaveOccurred())
			setAcceptedAndEnforcedConditionsToAuthPolicy(authPolicy)
			Expect(k8sClient.Status().Update(ctx, authPolicy)).ToNot(HaveOccurred())
		})

		It("should use cached OIDC discovery when issuer is unchanged", func() {
			By("First reconcile to set initial OIDC discovery")
			mockClient := &mockHTTPClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body: io.NopCloser(bytes.NewBufferString(`{
							"issuer": "` + TestIssuerURL + `",
							"token_endpoint": "` + CachedTokenEndpoint + `"
						}`)),
					}, nil
				},
			}

			controllerReconciler := &APIProductReconciler{
				Client:     k8sClient,
				Scheme:     k8sClient.Scheme(),
				HTTPClient: mockClient,
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			err = k8sClient.Get(ctx, apiProductKey, apiproduct)
			Expect(err).NotTo(HaveOccurred())
			Expect(apiproduct.Status.OIDCDiscovery).NotTo(BeNil())
			Expect(apiproduct.Status.OIDCDiscovery.TokenEndpoint).To(Equal(CachedTokenEndpoint))

			By("Second reconcile - should use cached value and not call HTTP client")
			// Track if HTTP client is called
			httpClientCalled := false
			mockClient.DoFunc = func(req *http.Request) (*http.Response, error) {
				httpClientCalled = true
				return &http.Response{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(bytes.NewBufferString(`{
						"issuer": "` + TestIssuerURL + `",
						"token_endpoint": "http://different.example.com/token"
					}`)),
				}, nil
			}

			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			// Assert HTTP client was never called (caching should skip discovery)
			Expect(httpClientCalled).To(BeFalse(), "HTTP client should not be called when using cached OIDC discovery")

			err = k8sClient.Get(ctx, apiProductKey, apiproduct)
			Expect(err).NotTo(HaveOccurred())
			Expect(apiproduct.Status.OIDCDiscovery).NotTo(BeNil())
			Expect(apiproduct.Status.OIDCDiscovery.TokenEndpoint).To(Equal(CachedTokenEndpoint))
		})
	})
})
