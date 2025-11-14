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

	devportalv1alpha1 "github.com/kuadrant/developer-portal-controller/api/v1alpha1"
)

var _ = Describe("APIKey Controller", func() {
	Context("When reconciling an APIKey with automatic approval", func() {
		const (
			apiKeyName     = "test-apikey-auto"
			apiProductName = "test-api-product"
			namespace      = "default"
		)

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      apiKeyName,
			Namespace: namespace,
		}

		BeforeEach(func() {
			By("Creating the APIProduct")
			apiProduct := &devportalv1alpha1.APIProduct{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiProductName,
					Namespace: namespace,
				},

				Spec: devportalv1alpha1.APIProductSpec{
					ApprovalMode: "automatic",
				},
			}
			Expect(k8sClient.Create(ctx, apiProduct)).To(Succeed())

			By("Creating the APIKey with automatic approval")
			apiKey := &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiKeyName,
					Namespace: namespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: &devportalv1alpha1.APIProductReference{
						Name:      apiProductName,
						Namespace: namespace,
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
			err := k8sClient.Get(ctx, typeNamespacedName, apiKey)
			if err == nil {
				Expect(k8sClient.Delete(ctx, apiKey)).To(Succeed())
			}

			By("Cleaning up the APIProduct")
			apiProduct := &devportalv1alpha1.APIProduct{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: apiProductName, Namespace: namespace}, apiProduct)
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
					NamespacedName: typeNamespacedName,
				})
				Expect(err).NotTo(HaveOccurred())
			}

			By("Checking the APIKey is approved")
			apiKey := &devportalv1alpha1.APIKey{}
			Eventually(func() string {
				err := k8sClient.Get(ctx, typeNamespacedName, apiKey)
				if err != nil {
					return ""
				}
				return apiKey.Status.Phase
			}, time.Second*10, time.Millisecond*250).Should(Equal("Approved"))

			By("Verifying reviewedBy is set to system")
			Expect(apiKey.Status.ReviewedBy).To(Equal("system"))

			By("Verifying the Secret reference exists")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, typeNamespacedName, apiKey)
				return err == nil && apiKey.Status.SecretRef != nil
			}, time.Second*1, time.Millisecond*250).Should(BeTrue())

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
			namespace      = "default"
		)

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      apiKeyName,
			Namespace: namespace,
		}

		BeforeEach(func() {
			By("Creating the APIProduct")
			apiProduct := &devportalv1alpha1.APIProduct{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiProductName,
					Namespace: namespace,
				},
				Spec: devportalv1alpha1.APIProductSpec{
					ApprovalMode: "manual",
				},
			}
			Expect(k8sClient.Create(ctx, apiProduct)).To(Succeed())

			By("Creating the APIKey with manual approval")
			apiKey := &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiKeyName,
					Namespace: namespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: &devportalv1alpha1.APIProductReference{
						Name:      apiProductName,
						Namespace: namespace,
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
			err := k8sClient.Get(ctx, typeNamespacedName, apiKey)
			if err == nil {
				Expect(k8sClient.Delete(ctx, apiKey)).To(Succeed())
			}

			By("Cleaning up the APIProduct")
			apiProduct := &devportalv1alpha1.APIProduct{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: apiProductName, Namespace: namespace}, apiProduct)
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
					NamespacedName: typeNamespacedName,
				})
				Expect(err).NotTo(HaveOccurred())
			}

			By("Checking the APIKey remains in Pending status")
			apiKey := &devportalv1alpha1.APIKey{}
			Consistently(func() string {
				err := k8sClient.Get(ctx, typeNamespacedName, apiKey)
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
				err := k8sClient.Get(ctx, typeNamespacedName, apiKey)
				return err == nil && apiKey.Status.SecretRef != nil
			}, time.Second*1, time.Millisecond*250).Should(BeFalse())
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
