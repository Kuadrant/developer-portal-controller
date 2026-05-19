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
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayapiv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	devportalv1alpha1 "github.com/kuadrant/developer-portal-controller/api/v1alpha1"
)

var _ = Describe("APIProduct OpenAPI Error Handling", func() {
	const (
		nodeTimeOut = NodeTimeout(30 * time.Second)
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
		deleteNamespaceWithContext(ctx, testNamespace)
	}, nodeTimeOut)

	Context("When OpenAPI fetch fails", func() {
		const (
			apiProductName    = "test-apiproduct-openapi-error"
			testURL           = "https://api2.example.com/spec.yaml"
			testGatewayName   = "my-gateway-openapi-error"
			testHTTPRouteName = "my-route-openapi-error"
		)

		ctx := context.Background()

		var (
			apiProductKey types.NamespacedName
			apiproduct    *devportalv1alpha1.APIProduct
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
						Name:  testHTTPRouteName,
						Kind:  "HTTPRoute",
					},
					PublishStatus: "Draft",
					ApprovalMode:  "manual",
					Documentation: &devportalv1alpha1.DocumentationSpec{
						OpenAPISpecURL: ptr.To(testURL),
					},
				},
			}

			gateway = buildBasicGateway(testGatewayName, testNamespace)
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			route = buildBasicHttpRoute(testHTTPRouteName, testGatewayName, testNamespace, []string{"openapi-error.example.com"})
			Expect(k8sClient.Create(ctx, route)).ToNot(HaveOccurred())
			addAcceptedCondition(route)
			Expect(k8sClient.Status().Update(ctx, route)).ToNot(HaveOccurred())
			Expect(k8sClient.Create(ctx, apiproduct)).ToNot(HaveOccurred())
		})

		It("should handle network errors gracefully", func() {
			By("Reconciling with mock HTTP client that returns network error")
			mockClient := &mockHTTPClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					// Simulate DNS lookup failure
					return nil, errors.New("dial tcp: lookup api2.example.com on 10.96.0.10:53: server misbehaving")
				},
			}

			controllerReconciler := &APIProductReconciler{
				Client:             k8sClient,
				Scheme:             k8sClient.Scheme(),
				HTTPClient:         mockClient,
				OpenAPISpecMaxSize: 500 * 1024,
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			// Reconcile should NOT return an error - the error should be in the status
			Expect(err).NotTo(HaveOccurred())

			err = k8sClient.Get(ctx, apiProductKey, apiproduct)
			Expect(err).NotTo(HaveOccurred())

			By("Checking OpenAPISpecReady condition is False")
			condition := meta.FindStatusCondition(apiproduct.Status.Conditions, devportalv1alpha1.StatusConditionOpenAPISpecReady)
			Expect(condition).NotTo(BeNil())
			Expect(condition.Status).To(Equal(metav1.ConditionFalse))
			Expect(condition.Reason).To(Equal("FetchFailed"))
			Expect(condition.Message).To(ContainSubstring("failed to fetch OpenAPI spec"))
			Expect(condition.Message).To(ContainSubstring("api2.example.com"))

			By("Checking OpenAPI status has empty content but timestamp")
			Expect(apiproduct.Status.OpenAPI).NotTo(BeNil())
			Expect(apiproduct.Status.OpenAPI.Raw).To(BeEmpty())
			Expect(apiproduct.Status.OpenAPI.LastSyncTime).NotTo(BeZero())
		})

		It("should handle HTTP error codes gracefully", func() {
			By("Reconciling with mock HTTP client that returns 404")
			mockClient := &mockHTTPClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusNotFound,
						Body:       io.NopCloser(bytes.NewBufferString("")),
					}, nil
				},
			}

			controllerReconciler := &APIProductReconciler{
				Client:             k8sClient,
				Scheme:             k8sClient.Scheme(),
				HTTPClient:         mockClient,
				OpenAPISpecMaxSize: 500 * 1024,
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			// Reconcile should NOT return an error - the error should be in the status
			Expect(err).NotTo(HaveOccurred())

			err = k8sClient.Get(ctx, apiProductKey, apiproduct)
			Expect(err).NotTo(HaveOccurred())

			By("Checking OpenAPISpecReady condition is False")
			condition := meta.FindStatusCondition(apiproduct.Status.Conditions, devportalv1alpha1.StatusConditionOpenAPISpecReady)
			Expect(condition).NotTo(BeNil())
			Expect(condition.Status).To(Equal(metav1.ConditionFalse))
			Expect(condition.Reason).To(Equal("FetchFailed"))
			Expect(condition.Message).To(ContainSubstring("unexpected status code 404"))
		})

		It("should recover when fetch succeeds after previous failure", func() {
			By("First reconcile with network error")
			mockClient := &mockHTTPClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					return nil, errors.New("network error")
				},
			}

			controllerReconciler := &APIProductReconciler{
				Client:             k8sClient,
				Scheme:             k8sClient.Scheme(),
				HTTPClient:         mockClient,
				OpenAPISpecMaxSize: 500 * 1024,
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			err = k8sClient.Get(ctx, apiProductKey, apiproduct)
			Expect(err).NotTo(HaveOccurred())

			condition := meta.FindStatusCondition(apiproduct.Status.Conditions, devportalv1alpha1.StatusConditionOpenAPISpecReady)
			Expect(condition).NotTo(BeNil())
			Expect(condition.Status).To(Equal(metav1.ConditionFalse))

			By("Updating spec to trigger a new fetch")
			apiproduct.Spec.DisplayName = "Updated Name"
			Expect(k8sClient.Update(ctx, apiproduct)).To(Succeed())

			By("Second reconcile with successful fetch")
			openAPIContent := `{"openapi": "3.0.0", "info": {"title": "Test API"}}`
			mockClient.DoFunc = func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(openAPIContent)),
				}, nil
			}

			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			err = k8sClient.Get(ctx, apiProductKey, apiproduct)
			Expect(err).NotTo(HaveOccurred())

			By("Checking OpenAPISpecReady condition is now True")
			condition = meta.FindStatusCondition(apiproduct.Status.Conditions, devportalv1alpha1.StatusConditionOpenAPISpecReady)
			Expect(condition).NotTo(BeNil())
			Expect(condition.Status).To(Equal(metav1.ConditionTrue))
			Expect(condition.Reason).To(Equal("SpecFetched"))

			By("Checking OpenAPI status has content")
			Expect(apiproduct.Status.OpenAPI).NotTo(BeNil())
			Expect(apiproduct.Status.OpenAPI.Raw).To(Equal(openAPIContent))
		})
	})
})
