/*
Copyright 2026.

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	devportalv1alpha1 "github.com/kuadrant/developer-portal-controller/api/v1alpha1"
)

var _ = Describe("APIKeyApproval Controller", func() {
	const (
		nodeTimeOut = NodeTimeout(time.Second * 30)
	)
	var (
		apiProductNamespace string
		consumerNamespace   string
		apiKeyName          = "test-apikey"
		apiProductName      = "test-api-product"
	)

	BeforeEach(func(ctx SpecContext) {
		createNamespaceWithContext(ctx, &apiProductNamespace)
		createNamespaceWithContext(ctx, &consumerNamespace)
	})

	AfterEach(func(ctx SpecContext) {
		deleteAPIKeysWithContext(ctx, consumerNamespace)
		deleteAPIKeyRequestsWithContext(ctx, apiProductNamespace)
		deleteAPIKeyApprovalsWithContext(ctx, apiProductNamespace)
		deleteNamespaceWithContext(ctx, apiProductNamespace)
		deleteNamespaceWithContext(ctx, consumerNamespace)
	}, nodeTimeOut)

	Context("When reconciling APIKeyApproval resources", func() {
		var (
			apiKey        *devportalv1alpha1.APIKey
			apiKeyRequest *devportalv1alpha1.APIKeyRequest
		)

		ctx := context.Background()

		BeforeEach(func() {
			By("Creating an APIKey in consumer namespace")
			apiKey = &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiKeyName,
					Namespace: consumerNamespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name:      apiProductName,
						Namespace: apiProductNamespace,
					},
					PlanTier: "premium",
					UseCase:  "Testing",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, apiKey)).To(Succeed())

			By("Creating an APIKeyRequest in apiproduct namespace")
			apiKeyRequest = &devportalv1alpha1.APIKeyRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      APIKeyRequestName(apiKey),
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyRequestSpec{
					APIProductRef: devportalv1alpha1.LocalAPIProductReference{
						Name: apiProductName,
					},
					PlanTier: "premium",
					UseCase:  "Testing",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
					APIKeyRef: devportalv1alpha1.APIKeyReference{
						Name:      apiKeyName,
						Namespace: consumerNamespace,
					},
				},
			}
			Expect(k8sClient.Create(ctx, apiKeyRequest)).To(Succeed())
		})

		It("should set owner reference for automatic garbage collection", func() {
			controllerReconciler := &APIKeyApprovalReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Creating an APIKeyApproval without owner reference")
			approval := &devportalv1alpha1.APIKeyApproval{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gc-test-approval",
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyApprovalSpec{
					APIKeyRequestRef: devportalv1alpha1.APIKeyRequestReference{
						Name: APIKeyRequestName(apiKey),
					},
					Approved:   true,
					ReviewedBy: "admin@example.com",
					ReviewedAt: metav1.Now(),
					Message:    "Testing owner reference",
				},
			}
			Expect(k8sClient.Create(ctx, approval)).To(Succeed())

			By("Verifying no owner reference exists initially")
			updatedApproval := &devportalv1alpha1.APIKeyApproval{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      "gc-test-approval",
				Namespace: apiProductNamespace,
			}, updatedApproval)).To(Succeed())
			Expect(updatedApproval.OwnerReferences).To(BeEmpty())

			By("Running reconciliation to set owner reference")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying owner reference is set correctly")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "gc-test-approval",
					Namespace: apiProductNamespace,
				}, updatedApproval)
				if err != nil {
					return false
				}
				// Check if owner reference is set with correct values
				if len(updatedApproval.OwnerReferences) == 0 {
					return false
				}
				ownerRef := updatedApproval.OwnerReferences[0]
				return ownerRef.Name == APIKeyRequestName(apiKey) &&
					ownerRef.Kind == "APIKeyRequest" &&
					ownerRef.APIVersion == "devportal.kuadrant.io/v1alpha1" &&
					ownerRef.Controller != nil && *ownerRef.Controller &&
					ownerRef.BlockOwnerDeletion != nil && *ownerRef.BlockOwnerDeletion
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())

			By("Verifying owner reference is idempotent (not duplicated on second reconcile)")
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      "gc-test-approval",
				Namespace: apiProductNamespace,
			}, updatedApproval)).To(Succeed())
			Expect(updatedApproval.OwnerReferences).To(HaveLen(1), "Should not create duplicate owner references")
		})
	})
})
