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
	corev1 "k8s.io/api/core/v1"
	_ "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayapiv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	devportalv1alpha1 "github.com/kuadrant/developer-portal-controller/api/v1alpha1"
)

var _ = Describe("APIKey Controller", func() {
	const (
		nodeTimeOut       = NodeTimeout(time.Second * 30)
		TestHTTPRouteName = "my-route"
	)
	var (
		testNamespace            string
		apiProductNamespacedName types.NamespacedName
		apiKeyNamespacedName     types.NamespacedName
		apiProduct               *devportalv1alpha1.APIProduct
		apiKey                   *devportalv1alpha1.APIKey
	)

	BeforeEach(func(ctx SpecContext) {
		createNamespaceWithContext(ctx, &testNamespace)
	})

	AfterEach(func(ctx SpecContext) {
		deleteNamespaceWithContext(ctx, &testNamespace)
	}, nodeTimeOut)

	Context("When reconciling an APIKey with automatic approval", func() {
		const (
			apiKeyName     = "test-apikey-auto"
			apiProductName = "test-api-product"
		)

		ctx := context.Background()

		BeforeEach(func() {
			By("Creating the APIProduct")
			apiProductNamespacedName = types.NamespacedName{
				Name:      apiProductName,
				Namespace: testNamespace,
			}
			apiProduct = &devportalv1alpha1.APIProduct{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiProductNamespacedName.Name,
					Namespace: apiProductNamespacedName.Namespace,
				},
				Spec: devportalv1alpha1.APIProductSpec{
					TargetRef: gatewayapiv1alpha2.LocalPolicyTargetReference{
						Group: gwapiv1.GroupName,
						Name:  TestHTTPRouteName,
						Kind:  "HTTPRoute",
					},
					PublishStatus: "Draft",
					ApprovalMode:  "automatic",
				},
			}
			Expect(k8sClient.Create(ctx, apiProduct)).To(Succeed())

			By("Creating the APIKey with automatic approval")
			apiKeyNamespacedName = types.NamespacedName{
				Name:      apiKeyName,
				Namespace: testNamespace,
			}
			apiKey = &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiKeyNamespacedName.Name,
					Namespace: apiKeyNamespacedName.Namespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: &devportalv1alpha1.APIProductReference{
						Name: apiProductNamespacedName.Name,
					},
					PlanTier: "premium",
					UseCase:  "Testing automatic approval",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, apiKey)).To(Succeed())
		})

		AfterEach(func() {
			By("Cleaning up the APIKey")
			apiKey := &devportalv1alpha1.APIKey{}
			err := k8sClient.Get(ctx, apiKeyNamespacedName, apiKey)
			if err == nil {
				Expect(k8sClient.Delete(ctx, apiKey)).To(Succeed())
			}

			By("Cleaning up the APIProduct")
			apiProduct := &devportalv1alpha1.APIProduct{}
			err = k8sClient.Get(ctx, apiKeyNamespacedName, apiProduct)
			if err == nil {
				Expect(k8sClient.Delete(ctx, apiProduct)).To(Succeed())
			}
		})

		It("should automatically approve and create Secret", func() {
			controllerReconciler := &APIKeyReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Running multiple reconciliation loops")
			for i := 0; i < 3; i++ {
				_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: apiKeyNamespacedName,
				})
				Expect(err).NotTo(HaveOccurred())
			}

			By("Checking the APIKey is approved")
			apiKey := &devportalv1alpha1.APIKey{}
			Eventually(func() string {
				err := k8sClient.Get(ctx, apiKeyNamespacedName, apiKey)
				if err != nil {
					return ""
				}
				return apiKey.Status.Phase
			}, time.Second*10, time.Millisecond*250).Should(Equal("Approved"))

			By("Verifying reviewedBy is set to system")
			Expect(apiKey.Status.ReviewedBy).To(Equal("system"))

			By("Checking the Secret was created")
			secret := &corev1.Secret{}
			secretKey := types.NamespacedName{
				Name:      apiKey.Status.SecretRef.Name,
				Namespace: apiKey.Namespace,
			}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, secretKey, secret)
				return err == nil
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())

			By("Verifying Secret has correct annotations")
			Expect(secret.Annotations).To(HaveKey(apiKeySecretAnnotationPlan))
			Expect(secret.Annotations).To(HaveKey(apiKeySecretAnnotationUser))
			Expect(secret.Annotations[apiKeySecretAnnotationPlan]).To(Equal("premium"))

			By("Verifying Secret has correct label")
			Expect(secret.Labels).To(HaveKey("app"))
			Expect(secret.Labels["app"]).To(Equal(apiProductName))
		})
	})

	Context("When reconciling an APIKey with manual approval", func() {
		const (
			apiKeyName     = "test-apikey-manual"
			apiProductName = "test-api-product-manual"
		)

		ctx := context.Background()

		apiKeyNamespacedName := types.NamespacedName{
			Name:      apiKeyName,
			Namespace: testNamespace,
		}

		BeforeEach(func() {
			By("Creating the APIProduct")
			apiProductNamespacedName = types.NamespacedName{
				Name:      apiProductName,
				Namespace: testNamespace,
			}
			apiProduct = &devportalv1alpha1.APIProduct{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiProductNamespacedName.Name,
					Namespace: apiProductNamespacedName.Namespace,
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
			Expect(k8sClient.Create(ctx, apiProduct)).To(Succeed())

			By("Creating the APIKey with manual approval")
			apiKeyNamespacedName = types.NamespacedName{
				Name:      apiKeyName,
				Namespace: testNamespace,
			}
			apiKey = &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiKeyNamespacedName.Name,
					Namespace: apiKeyNamespacedName.Namespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: &devportalv1alpha1.APIProductReference{
						Name: apiProductNamespacedName.Name,
					},
					PlanTier: "enterprise",
					UseCase:  "Testing manual approval",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "manual-user",
						Email:  "manual@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, apiKey)).To(Succeed())
		})

		AfterEach(func() {
			By("Cleaning up the APIKey")
			apiKey := &devportalv1alpha1.APIKey{}
			err := k8sClient.Get(ctx, apiKeyNamespacedName, apiKey)
			if err == nil {
				Expect(k8sClient.Delete(ctx, apiKey)).To(Succeed())
			}

			By("Cleaning up the APIProduct")
			apiProduct := &devportalv1alpha1.APIProduct{}
			err = k8sClient.Get(ctx, apiProductNamespacedName, apiProduct)
			if err == nil {
				Expect(k8sClient.Delete(ctx, apiProduct)).To(Succeed())
			}
		})

		It("should remain in Pending status without automatic approval", func() {
			controllerReconciler := &APIKeyReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Running multiple reconciliation loops")
			for i := 0; i < 3; i++ {
				_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: apiKeyNamespacedName,
				})
				Expect(err).NotTo(HaveOccurred())
			}

			By("Checking the APIKey remains in Pending status")
			apiKey := &devportalv1alpha1.APIKey{}
			Consistently(func() string {
				err := k8sClient.Get(ctx, apiKeyNamespacedName, apiKey)
				if err != nil {
					return ""
				}
				return apiKey.Status.Phase
			}, time.Second*5, time.Millisecond*250).Should(Equal("Pending"))

			By("Verifying the Condition type Approved is False")
			Expect(apiKey.Status.Conditions[0].Type).Should(Equal("Ready"))
			Expect(apiKey.Status.Conditions[0].Status).Should(Equal(metav1.ConditionFalse))
			Expect(apiKey.Status.Conditions[0].Reason).Should(Equal("NotApproved"))

			By("Verifying the Secret was not created")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, apiKeyNamespacedName, apiKey)
				return err == nil && apiKey.Status.SecretRef != nil
			}, time.Second*1, time.Millisecond*250).Should(BeFalse())
		})
	})

	Context("When reconciling a Rejected APIKey", func() {
		const (
			apiKeyName     = "test-apikey-rejected"
			apiProductName = "test-api-product-rejected"
		)

		ctx := context.Background()

		BeforeEach(func() {
			By("Creating the APIProduct")
			apiProductNamespacedName = types.NamespacedName{
				Name:      apiProductName,
				Namespace: testNamespace,
			}
			apiProduct = &devportalv1alpha1.APIProduct{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiProductNamespacedName.Name,
					Namespace: apiProductNamespacedName.Namespace,
				},
				Spec: devportalv1alpha1.APIProductSpec{
					TargetRef: gatewayapiv1alpha2.LocalPolicyTargetReference{
						Group: gwapiv1.GroupName,
						Name:  TestHTTPRouteName,
						Kind:  "HTTPRoute",
					},
					PublishStatus: "Draft",
					ApprovalMode:  "automatic",
				},
			}
			Expect(k8sClient.Create(ctx, apiProduct)).To(Succeed())

			By("Creating the APIKey")
			apiKeyNamespacedName = types.NamespacedName{
				Name:      apiKeyName,
				Namespace: testNamespace,
			}
			apiKey = &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiKeyNamespacedName.Name,
					Namespace: apiKeyNamespacedName.Namespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: &devportalv1alpha1.APIProductReference{
						Name: apiProductNamespacedName.Name,
					},
					PlanTier: "basic",
					UseCase:  "Testing rejection",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "rejected-user",
						Email:  "rejected@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, apiKey)).To(Succeed())
		})

		AfterEach(func() {
			By("Cleaning up the APIKey")
			apiKey := &devportalv1alpha1.APIKey{}
			err := k8sClient.Get(ctx, apiKeyNamespacedName, apiKey)
			if err == nil {
				Expect(k8sClient.Delete(ctx, apiKey)).To(Succeed())
			}

			By("Cleaning up the APIProduct")
			apiProduct := &devportalv1alpha1.APIProduct{}
			err = k8sClient.Get(ctx, apiProductNamespacedName, apiProduct)
			if err == nil {
				Expect(k8sClient.Delete(ctx, apiProduct)).To(Succeed())
			}
		})

		It("should delete the Secret and update status when rejected", func() {
			controllerReconciler := &APIKeyReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Running reconciliation to approve and create Secret")
			for i := 0; i < 3; i++ {
				_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: apiKeyNamespacedName,
				})
				Expect(err).NotTo(HaveOccurred())
			}

			By("Verifying the APIKey is approved and Secret is created")
			apiKey := &devportalv1alpha1.APIKey{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, apiKeyNamespacedName, apiKey)
				return err == nil && apiKey.Status.Phase == "Approved" && apiKey.Status.SecretRef != nil
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())

			By("Verifying the Secret exists")
			secret := &corev1.Secret{}
			secretKey := types.NamespacedName{
				Name:      apiKey.Status.SecretRef.Name,
				Namespace: apiKey.Namespace,
			}
			err := k8sClient.Get(ctx, secretKey, secret)
			Expect(err).NotTo(HaveOccurred())

			By("Changing the APIKey phase to Rejected")
			err = k8sClient.Get(ctx, apiKeyNamespacedName, apiKey)
			Expect(err).NotTo(HaveOccurred())
			apiKey.Status.Phase = "Rejected"
			err = k8sClient.Status().Update(ctx, apiKey)
			Expect(err).NotTo(HaveOccurred())

			By("Running reconciliation for the rejected APIKey")
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: apiKeyNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the Secret was deleted")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, secretKey, secret)
				return err != nil
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())

			By("Verifying the SecretRef is cleared from status")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, apiKeyNamespacedName, apiKey)
				return err == nil && apiKey.Status.SecretRef == nil
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())

			By("Verifying the Ready condition is set to False with Rejected reason")
			err = k8sClient.Get(ctx, apiKeyNamespacedName, apiKey)
			Expect(err).NotTo(HaveOccurred())
			Expect(apiKey.Status.Conditions).ToNot(BeEmpty())

			readyCondition := apiKey.Status.Conditions[len(apiKey.Status.Conditions)-1]
			Expect(readyCondition.Type).To(Equal("Ready"))
			Expect(readyCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(readyCondition.Reason).To(Equal("Rejected"))
			Expect(readyCondition.Message).To(Equal("API key request has been rejected"))
		})
	})

	Context("Helper functions", func() {
		It("should generate unique API keys", func() {
			key1, err1 := generateAPIKey()
			key2, err2 := generateAPIKey()

			Expect(err1).NotTo(HaveOccurred())
			Expect(err2).NotTo(HaveOccurred())
			Expect(key1).NotTo(Equal(key2))
			Expect(key1).ToNot(BeEmpty())
			Expect(key2).ToNot(BeEmpty())
		})
	})
})
